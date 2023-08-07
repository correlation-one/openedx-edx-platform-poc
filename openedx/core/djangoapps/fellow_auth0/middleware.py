import json
import os
import requests
import secrets
import string

from datetime import datetime
from pathlib import Path
from logging import getLogger
from jose import jwt

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from common.djangoapps.student.models import (
    UserProfile,
    Registration
)
logger = getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH0_ALGORITHMS = ["RS256"]
AUTH0_JWKS_DIR = os.path.join(BASE_DIR, "fellow_auth0", "auth0")
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


class SetUserFromAuth0Token:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth0_authenticator = Auth0TokenAuthentication()

    def __call__(self, request):

        print("=====***C1 OPENEDX PoC***=====")        

        try:
            authenticate_header = self.auth0_authenticator.authenticate_header(request)
            logger.info(authenticate_header)
            training_edx_user = self.auth0_authenticator.authenticate(request)
            request.user = training_edx_user

        except Exception as error:
            print(error)

        response = self.get_response(request)

        print("=======*C1 OPENEDX PoC*=======") 

        return response


class Auth0TokenAuthentication(BaseAuthentication):
    """
    Auth0 token based authentication.

    - This class authenticates users against the Auth0 API via the Bearer token.
    - If the token can be validated correctly it adds the user to the request

    This is an adaptation of training-server similar module found in:
    - /training-server/src/core/authentication.py
    """

    # this setting determines if the Auth0 JWKS file needs to be updated
    MAX_JWKS_UPDATE_HOURS = 12

    def authenticate_header(self, request):
        # When a custom authentication method is implemented and is located at the
        # beginning of DEFAULT_AUTHENTICATION_CLASSES, it must implement this method
        # to indicate the client how to authenticate. This implementation will return a
        # 401 status, if not implemented 403. Reference (Custom authentication header):
        # https://www.django-rest-framework.org/api-guide/authentication/
        return "Bearer realm=token"

    def authenticate(self, request):
        auth_header = get_authorization_header(request).split()
        # validate if the header contains the expected content
        if not auth_header or auth_header[0].lower() != "Bearer".lower().encode():
            logger.warning("Received an authentication header without 'Bearer' token")
            raise BearerTokenNotPresentError(message="C1 PoC: bearer token not present in authentication header")
        if len(auth_header) == 1 or len(auth_header) > 2:
            logger.warning("Provided authentication header has an unexpected length")
            raise BearerTokenNotPresentError(message="C1 PoC: authentication header has an unexpected length")
        # obtain the token and try to authenticate against Auth0
        token = auth_header[1]
        return self._authenticate_token(token)

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
        username = "middleware_generated_"+name.replace(" ", "_").lower()
        logger.info(f"auth0 user has email {email}")

        if not email:
            logger.warning("Impossible to get the user data from Auth0")
            raise UserDoesNotExistsError(message="Cannot get user data from Auth0")

        if get_user_model().objects.filter(email__iexact=email).exists():
            training_user = get_user_model().objects.get(email__iexact=email)
            # if the user exists but does not have an Auth0 UUID, update the data
            # training_user.auth0_uuid = auth0_uuid
            try:
                training_user.save()
            except Exception:
                logger.exception(f"User creation failed for user with email {email}.")
                raise
            logger.info(
                f"Updated user '{training_user}' with the Auth0 UUID '{auth0_uuid}'"
            )
        else:
            logger.info(
                f"User with email '{email}' does not exists on OpenEdx DB "
            )
            # create the user if it doesn't exist in the openedx db
            training_user = get_user_model().objects.create(username=username, email=email,is_active=True)
            training_user.set_unusable_password()
            training_user.save()

            # Replicating what do_create_account does, create a registration and a profile
            registration = Registration()
            registration.register(training_user)

            profile = UserProfile(
                user=training_user,
                name=name,
                gender="nb",
                year_of_birth=1992
                )
            try:
                profile.save()
            except Exception:
                logger.exception(f"UserProfile creation failed for user {training_user.id}.")
                raise
            logger.info(
                f"User with email '{email}' created in OpenEdx DB"
            )

        return training_user

    def _is_valid_auth0_token(self, token):
        jwks = self._get_auth0_jwks()

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
                url = AUTH0_DOMAIN + "/.well-known/jwks.json"
                resp = requests.get(url)
                jwks = resp.json()
                # creates the directory and file if does not exist and write the JWKS
                Path(AUTH0_JWKS_DIR).mkdir(parents=True, exist_ok=True)
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
