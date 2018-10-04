from flask import request
from functools import wraps
from jose import jwk, jwt
from jose.utils import base64url_decode
from werkzeug.routing import BaseConverter, ValidationError
import datetime
import json
import urllib.request

from .exceptions import UnauthorizedException, InvalidSchemaException, ForbiddenException
from ..api.config import Config


# Using classes as namespaces
# noinspection PyPep8Naming
class require:

    # noinspection PyPep8Naming
    class authenticated:

        @staticmethod
        def any(decorated_function):
            """
            Decorator to require a JWT token to be passed.
            """
            @wraps(decorated_function)
            def wrapper(*args, **kwargs):
                if 'Authorization' not in request.headers:
                    raise UnauthorizedException("Unauthorized")
                principal_id = _authenticate_jwt(request.headers['Authorization'])

                # Try passing the principal_id to the internal function, but this will fail if the function definition
                # doesn't 'want' the parameter by specifying a named parameter value for it
                try:
                    kwargs['principal_id'] = principal_id
                    return decorated_function(*args, **kwargs)
                except TypeError:
                    del kwargs['principal_id']
                    return decorated_function(*args, **kwargs)
            return wrapper

        @staticmethod
        def self(decorated_function):
            """
            Decorator to require a JWT token to be passed, and for the principal_id of the JWT to match the first
            parameter in the route function call.
            """
            @wraps(decorated_function)
            def wrapper(*args, **kwargs):
                if 'Authorization' not in request.headers:
                    raise UnauthorizedException("Unauthorized")
                principal_id = _authenticate_jwt(request.headers['Authorization'])
                if len(kwargs) == 0 or list(kwargs.values())[0] != principal_id:
                    raise UnauthorizedException("You may only execute this action on yourself")
                return decorated_function(*args, **kwargs)
            return wrapper

        @staticmethod
        def service(decorated_function):
            """
            Decorator to require a JWT token to be passed, and for the principal_id of the JWT to be the 'magic' value.
            """
            @wraps(decorated_function)
            def wrapper(*args, **kwargs):
                if 'Authorization' not in request.headers:
                    raise UnauthorizedException("Unauthorized")
                principal_id = _authenticate_jwt(request.headers['Authorization'])
                if principal_id != '00000000-0000-4000-8000-000000000000':
                    raise ForbiddenException("This endpoint may only be called internally")
                return decorated_function(*args, **kwargs)
            return wrapper

    # TODO this could be a class
    @staticmethod
    def body(required_body):
        def validate_request():
            if request.json is None or not isinstance(request.json, dict):
                t = type(request.json)
                raise InvalidSchemaException(f'Request body must be a JSON object, not "{t}"')
            validate_dict(request.json, required_body)

        def validate_dict(body, schema, prefix=''):
            if not isinstance(body, dict):
                raise InvalidSchemaException(f"Property '{prefix}' must be a dictionary")

            if prefix != '':
                prefix += '.'

            for key, key_schema in schema.items():
                value = body.get(key, None)
                if value is None:
                    if isinstance(key_schema, (tuple, list)) and None in key_schema:
                        # Absence of key is allowed
                        continue
                    elif key in body:
                        raise InvalidSchemaException(f"Property '{prefix}{key}' cannot be null")
                    else:
                        raise InvalidSchemaException(f"Property '{prefix}{key}' is required")

                if isinstance(key_schema, (tuple, list)):
                    key_schema = tuple(filter(None, key_schema))
                    if len(key_schema) == 1:
                        key_schema = key_schema[0]

                if isinstance(key_schema, dict):
                    validate_dict(body[key], key_schema, prefix=f'{prefix}{key}')

                # TODO basic type validation
                elif isinstance(key_schema, (str, int, float, bool)):
                    pass

                elif issubclass(key_schema, BaseConverter):
                    # Validate
                    try:
                        key_schema.to_python(None, value)
                    except ValidationError:
                        type_name = getattr(key_schema, 'type_name', key_schema.__name__)
                        raise InvalidSchemaException(f"Property '{prefix}{key}' must be of type '{type_name}'")

                else:
                    pass

        def wrap(original_function):
            @wraps(original_function)
            def wrapped_function(*args, **kwargs):
                validate_request()
                return original_function(*args, **kwargs)

            return wrapped_function
        return wrap


def _authenticate_jwt(raw_token):

    try:
        token = jwt.get_unverified_claims(raw_token)
        public_key = _get_rs256_public_key(raw_token)

        message, encoded_signature = str(raw_token).rsplit('.', 1)
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise UnauthorizedException('Signature verification failed')

        print({'jwt_token': token})

        for field in ['cognito:username', 'username', 'sub']:
            if field in token:
                principal_id = token[field]
                break
        else:
            raise UnauthorizedException('No principal id in token')

        if 'exp' not in token:
            raise UnauthorizedException('No expiry time in token')
        expiry_date = datetime.datetime.fromtimestamp(token['exp'])
        now = datetime.datetime.utcnow()
        if expiry_date < now:
            raise UnauthorizedException(f'Token has expired: {expiry_date.isoformat()} < {now.isoformat()}')

        return principal_id

    except UnauthorizedException:
        raise
    except Exception:
        raise UnauthorizedException('JWT token verification failed')


cognito_keys_cache = {}


def _get_rs256_public_key(raw_token):
    key_id = jwt.get_unverified_header(raw_token)['kid']

    if key_id not in cognito_keys_cache:
        token = jwt.get_unverified_claims(raw_token)
        cognito_userpool_id = token['iss'].split('/')[-1]
        cognito_keys_url = f'https://cognito-idp.{Config.get("AWS_DEFAULT_REGION")}.amazonaws.com/{cognito_userpool_id}/.well-known/jwks.json'
        print(f'Loading new keys from {cognito_keys_url}')
        keys = json.loads(urllib.request.urlopen(cognito_keys_url).read())
        cognito_keys_cache.update({k['kid']: k for k in keys['keys']})

    if key_id not in cognito_keys_cache:
        raise UnauthorizedException('Unknown signing key')

    return jwk.construct(cognito_keys_cache[key_id])
