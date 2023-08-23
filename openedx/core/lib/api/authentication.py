""" Common Authentication Handlers used across projects. """

import logging
import json
import os
import requests
import secrets
import string
from datetime import datetime
from pathlib import Path
from logging import getLogger
from jose import jwt

import django.utils.timezone
from django.contrib.auth import get_user_model

from oauth2_provider import models as dot_models
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from edx_django_utils.monitoring import set_custom_attribute

OAUTH2_TOKEN_ERROR = 'token_error'
OAUTH2_TOKEN_ERROR_EXPIRED = 'token_expired'
OAUTH2_TOKEN_ERROR_MALFORMED = 'token_malformed'
OAUTH2_TOKEN_ERROR_NONEXISTENT = 'token_nonexistent'
OAUTH2_TOKEN_ERROR_NOT_PROVIDED = 'token_not_provided'
OAUTH2_USER_NOT_ACTIVE_ERROR = 'user_not_active'
OAUTH2_USER_DISABLED_ERROR = 'user_is_disabled'


logger = logging.getLogger(__name__)

# ...................................................................................
# ....................................OpenEdx PoC....................................

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH0_ALGORITHMS = ["RS256"]
AUTH0_JWKS_DIR = os.path.join(BASE_DIR, "api", "auth0")
AUTH0_JWKS_FILE_PATH = AUTH0_JWKS_DIR + "/jwks.json"

# AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
# DEV DOMAIN: AUTH0_DOMAIN="https://correlation-one-dev.us.auth0.com"
AUTH0_DOMAIN="https://dev-gmbj6vsq.us.auth0.com"
if AUTH0_DOMAIN is None:
    logger.error("KEY_IS_NOT_SET: AUTH0_DOMAIN")

# AUTH0_API_AUDIENCE = os.getenv("AUTH0_API_AUDIENCE")
# DEV AUDIENCE: AUTH0_API_AUDIENCE="https://correlation-one-dev.us.auth0.com/api/v2/"
AUTH0_API_AUDIENCE="https://dev-gmbj6vsq.us.auth0.com/userinfo"
if AUTH0_API_AUDIENCE is None:
    logger.error("KEY_IS_NOT_SET: AUTH0_API_AUDIENCE")

AUTH0_ISSUER="https://login.correlation-one.com/"


class BearerTokenNotPresentError(Exception):
    """Raise when the expected bearer token is not present in the incomming request"""

    def __init__(self, message):
        super().__init__(message)


class InvalidBearerTokenError(Exception):
    """Raise when token is invalid, for example if it has expired"""

    def __init__(self, message):
        super().__init__(message)


class UserDoesNotExistsError(Exception):
    """Raise when the user does not exist in OpenEdx DB"""

    def __init__(self, message):
        super().__init__(message)


class BearerAuthentication(BaseAuthentication):
    """
    BearerAuthentication backend using either `django-oauth2-provider` or 'django-oauth-toolkit'
    """

    # this setting determines if the Auth0 JWKS file needs to be updated
    MAX_JWKS_UPDATE_HOURS = 12
    www_authenticate_realm = 'api'

    # currently, active users are users that confirm their email.
    # a subclass could override `allow_inactive_users` to enable access without email confirmation,
    # like in the case of mobile users.
    allow_inactive_users = False

    def authenticate(self, request):
        """
        Returns tuple (user, token) if access token authentication  succeeds,
        returns None if the user did not try to authenticate using an access
        token, or raises an AuthenticationFailed (HTTP 401) if authentication
        fails.
        """

        set_custom_attribute("BearerAuthentication", "Failed")  # default value

        print("=====***C1 OPENEDX PoC: BearerAuthentication***=====")

        auth = get_authorization_header(request).split()

        if len(auth) == 1:  # lint-amnesty, pylint: disable=no-else-raise
            raise AuthenticationFailed({
                'error_code': OAUTH2_TOKEN_ERROR_NOT_PROVIDED,
                'developer_message': 'Invalid token header. No credentials provided.'})
        elif len(auth) > 2:
            raise AuthenticationFailed({
                'error_code': OAUTH2_TOKEN_ERROR_MALFORMED,
                'developer_message': 'Invalid token header. Token string should not contain spaces.'})

        if auth and auth[0].lower() == b'bearer':
            access_token = auth[1].decode('utf8')
        else:
            set_custom_attribute("BearerAuthentication", "None")
            return None

        user = self._authenticate_token(access_token)
        token = auth[1]

        set_custom_attribute("BearerAuthentication", "Success")

        return user, token

    def _authenticate_token(self, token):
        payload, is_valid = self._is_valid_auth0_token(token)
        if not is_valid:
            raise InvalidBearerTokenError("C1 PoC: invalid token")

        logger.info("token is valid")

        # the key 'sub' contains the Auth0 UUID of the user
        auth0_uuid = payload["sub"]

        # we would need to set the auth0_uuid on OpenEdx DB - but for the moment ignore this
        #
        # training_user = get_user_model().objects.get(auth0_uuid=auth0_uuid)
        # get_user_model().DoesNotExist:
        #

        user_data = self._get_user_data_from_auth0(token)
        # user data contains: name, nickname, email, picture, updated_at, email_verified
        email = user_data.get("email")
        name = user_data.get('name')
        logger.info(f"auth0 user has email {email}")

        if not email:
            logger.warning("Impossible to get the user data from Auth0")
            raise UserDoesNotExistsError(message="Cannot get user data from Auth0")

        if get_user_model().objects.filter(email__iexact=email).exists():
            training_user = get_user_model().objects.get(email__iexact=email)
            # if the user exists but does not have an Auth0 UUID, update the data
            # training_user.auth0_uuid = auth0_uuid
            training_user.save()
            logger.info(
                f"Updated user '{training_user}' with the Auth0 UUID '{auth0_uuid}'"
            )
        else:
            logger.info(
                f"User with email '{email}' does not exists on OpenEdx DB "
            )
            # create the user if it doesn't exist in the openedx db
            password = self._get_random_password()
            training_user = get_user_model().objects.create(username=name, email=email, password=password)
            logger.info(
                f"User with email '{email}' created in OpenEdx DB"
            )

        return training_user

    def _is_valid_auth0_token(self, token):
        jwks = self._get_auth0_jwks()
        logger.info("Got jwks")
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception:
            logger.warning("Not possible to get the unverified header of the token")
            unverified_header = None

        rsa_key = {}
        # validate the keys if they match
        if jwks and isinstance(unverified_header, dict) and len(unverified_header) > 0:
            for key in jwks["keys"]:
                if key["kid"] == unverified_header.get("kid"):
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"],
                    }
        if rsa_key:
            # decode the token and return the payload or the error
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=AUTH0_ALGORITHMS,
                    audience=AUTH0_API_AUDIENCE,
                    issuer=AUTH0_ISSUER,
                )
                return payload, True
            except Exception as ex:
                # The exception can be triggered if it is not possible to decode the
                # JWT. Can be multiple problems of it, like if the token is expired, or
                # if the audience or issuer are not correct, or a parsing problem
                # when the token has an invalid format. In such a cases the exceptions
                # will be jwt.ExpiredSignatureError, jwt.JWTClaimsError or the common
                # Exception. If at some point it is necessary to send the exception
                # messages to the client (by raising an exception) or log it, implement
                # the specific except clause and raise it as follows:
                # raise exceptions.AuthenticationFailed(message)
                # For now, this clause does nothing.
                logger.warning(f"Not possible to decode the token. Ex: {ex}")

        return {}, False

    def _get_user_data_from_auth0(self, token):
        try:
            url = AUTH0_API_AUDIENCE
            params = {"access_token": token}
            resp = requests.get(url, params)
            data = resp.json()
            return data
        except Exception:
            logger.error(f"Impossible to get the Auth0 user info from {url}")

    def _get_auth0_jwks(self):
        """Obtain the JSON Web Key Set from Auth0 or from a local file"""

        def __get_auth0_jwks_last_modified_hours():
            try:
                last_modified_epoch = os.path.getmtime(AUTH0_JWKS_FILE_PATH)
                last_modified_datetime = datetime.fromtimestamp(last_modified_epoch)
                diff = datetime.now() - last_modified_datetime
                diff_hours = int(diff.seconds / 60 / 60)
                return diff_hours
            except Exception:
                return self.MAX_JWKS_UPDATE_HOURS

        try:
            # check if the JWKS file doesn't exist or if it needs to be updated
            if (
                not os.path.exists(AUTH0_JWKS_FILE_PATH)
                or __get_auth0_jwks_last_modified_hours() >= self.MAX_JWKS_UPDATE_HOURS
            ):
                resp = requests.get(
                    AUTH0_DOMAIN + "/.well-known/jwks.json"
                )
                jwks = resp.json()
                # creates the directory and file if does not exist and write the JWKS
                Path(AUTH0_JWKS_DIR).mkdir(parents=True, exist_ok=True)
                logger.info(f"New JWKS file will be created: {AUTH0_JWKS_FILE_PATH}")
                with open(AUTH0_JWKS_FILE_PATH, "w") as json_file:
                    json.dump(jwks, json_file, indent=4)

            # by reading the file locally instead of doing it from the Auth0 API, it
            # saves to execte an unnecessary request against the Auth0.
            with open(AUTH0_JWKS_FILE_PATH) as json_file:
                return json.load(json_file)
        except Exception as e:
            logger.error(f"Error while trying to get the Auth0 JWKS. Exception: {e}")

    def _get_random_password(self, password_lenght=24):
        return "".join(
            secrets.choice(
                string.ascii_uppercase
                + string.ascii_lowercase
                + string.digits
                + string.punctuation
            )
            for i in range(password_lenght)
        )

    def get_access_token(self, access_token):
        """
        Return a valid access token stored by django-oauth-toolkit (DOT), or
        None if no matching token is found.
        """
        token_query = dot_models.AccessToken.objects.select_related('user')
        return token_query.filter(token=access_token).first()

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response
        """
        return 'Bearer realm="%s"' % self.www_authenticate_realm


class BearerAuthenticationAllowInactiveUser(BearerAuthentication):
    """
    Currently, is_active field on the user is coupled
    with whether or not the user has verified ownership of their claimed email address.
    Once is_active is decoupled from verified_email, we will no longer need this
    class override.

    This class can be used for an OAuth2-accessible endpoint that allows users to access
    that endpoint without having their email verified.  For example, this is used
    for mobile endpoints.
    """

    allow_inactive_users = True


class OAuth2Authentication(BearerAuthentication):
    """
    Creating temperary class cause things outside of edx-platform need OAuth2Authentication.
    This will be removed when repos outside edx-platform import BearerAuthentiction instead.
    """


class OAuth2AuthenticationAllowInactiveUser(BearerAuthenticationAllowInactiveUser):
    """
    Creating temperary class cause things outside of edx-platform need OAuth2Authentication.
    This will be removed when repos outside edx-platform import BearerAuthentiction instead.
    """
