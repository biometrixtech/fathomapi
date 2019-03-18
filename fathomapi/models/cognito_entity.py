from ._entity import Entity, ReturnValuedGenerator
from abc import abstractmethod
from botocore.exceptions import ClientError, ParamValidationError
import boto3
import datetime
import json
import math

from fathomapi.utils.exceptions import NoSuchEntityException, DuplicateEntityException, InvalidPasswordFormatException, UnauthorizedException


_cognito_client = boto3.client('cognito-idp')


class CognitoEntity(Entity):
    _id = None

    @classmethod
    @abstractmethod
    def user_pool_id(cls):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def user_pool_client_id(cls):
        raise NotImplementedError

    @property
    def id(self):
        if self._id is None:
            self._fetch()
        return self._id

    def get(self, include_internal_properties=False):
        ret = super().get(include_internal_properties)
        ret['id'] = self._id
        return ret

    @classmethod
    def _get_many(cls, next_token=None, max_items=math.inf, **kwargs):
        args = {'UserPoolId': cls.user_pool_id(), 'Limit': min(max_items, 60)}
        if len(kwargs) == 1:
            key, value = next(iter(kwargs.items()))
            if key not in ['id']:
                raise NotImplementedError('CognitoEntity.get_many() can only be filtered on `id` property')
            filter_function = lambda u: getattr(u, key) in value
        elif len(kwargs) > 1:
            raise NotImplementedError('CognitoEntity.get_many() can only be filtered on one property')
        else:
            filter_function = lambda u: True

        if next_token is not None:
            args['PaginationToken'] = next_token

        res = _cognito_client.list_users(**args)

        count = 0
        for user in res['Users']:
            obj = cls(user['Username'])
            obj._hydrate(user['Attributes'])
            obj._id = user['Username']

            if filter_function(obj):
                yield obj
                count += 1

        next_next_token = res.get('PaginationToken', None)

        if next_next_token is not None and count < max_items:
            ret = cls.get_many(next_token=next_next_token, max_items=max_items - count, **kwargs)
            yield from ret
            return ret.value

        return next_next_token

    def _fetch(self):
        try:
            res = _cognito_client.admin_get_user(
                UserPoolId=self.user_pool_id(),
                Username=self.id,
            )
            self._id = res['Username']
            return {prop['Name'].split(':')[-1]: prop['Value'] for prop in res['UserAttributes']}

        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise

    def patch(self, body):
        self.validate('PATCH', body)
        return self._patch(self.get_fields(immutable=False, primary_key=False), body)

    def _patch(self, fields, body):
        attributes_to_update = []
        attributes_to_delete = []

        body = self.flatten(body)

        for key in fields:
            if key in body:
                param_name = key if key in ['email_verified'] else f'custom:{key}'
                if body[key] is None:
                    attributes_to_delete.append(param_name)
                else:
                    attributes_to_update.append({'Name': param_name, 'Value': body[key]})

        if self.exists():
            _cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id(),
                Username=self.id,
                UserAttributes=attributes_to_update
            )
            _cognito_client.admin_delete_user_attributes(
                UserPoolId=self.user_pool_id(),
                Username=self.id,
                UserAttributeNames=attributes_to_delete
            )
        else:
            # TODO
            raise NotImplementedError('Cannot patch, user does not exist')

        return self.get()

    def create(self, body):
        body['updated_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        body['created_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.validate('PUT', body)

        try:
            params = {
                'UserPoolId': self.user_pool_id(),
                'Username': self.id,
                'TemporaryPassword': body['password'],
                'UserAttributes': [{'Name': 'email', 'Value': body['personal_data']['email']}],
                'MessageAction': 'SUPPRESS',
            }

            for key in self.get_fields(primary_key=False):
                if key in body and key != 'password':
                    param_name = key if key in ['email_verified'] else 'custom:{}'.format(key)
                    params['UserAttributes'].append({'Name': param_name, 'Value': body[key]})

            _cognito_client.admin_create_user(**params)
            self._exists = True

            # Log in straight away so there's no risk of the Cognito user expiring
            self.login(password=body['password'])

            self._fetch()
            return self.id

        except ClientError as e:
            if 'UsernameExistsException' in str(e):
                raise DuplicateEntityException()
            if 'InvalidPasswordException' in str(e):
                raise InvalidPasswordFormatException('Password does not meet security requirements')
            else:
                raise
        except ParamValidationError as e:
            if 'Invalid length for parameter TemporaryPassword' in str(e):
                raise InvalidPasswordFormatException('Password is too short')
            else:
                raise

    def delete(self):
        try:
            _cognito_client.admin_delete_user(
                UserPoolId=self.user_pool_id(),
                Username=self.id
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise e

    def login(self, *, password=None, token=None):
        if not self.exists():
            raise NoSuchEntityException()

        if password is not None:
            return self._login_password(password)
        elif token is not None:
            return self._login_token(token)
        else:
            raise Exception('Either password or token must be given')

    def _login_password(self, password):
        try:
            response = _cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id(),
                ClientId=self.user_pool_client_id(),
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': self.id,
                    'PASSWORD': password
                },
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            if 'NotAuthorizedException' in str(e):
                details = str(e).split(':')[-1].strip(' ')
                raise UnauthorizedException(details)
            raise
        if 'ChallengeName' in response and response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
            # Need to set a new password
            response = _cognito_client.admin_respond_to_auth_challenge(
                UserPoolId=self.user_pool_id(),
                ClientId=self.user_pool_client_id(),
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={'USERNAME': self.id, 'NEW_PASSWORD': password},
                Session=response['Session']
            )

        expiry_date = datetime.datetime.now() + datetime.timedelta(seconds=response['AuthenticationResult']['ExpiresIn'])
        return {
            'jwt': response['AuthenticationResult']['IdToken'],
            'access_token': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': response['AuthenticationResult']['RefreshToken'],
        }

    def _login_token(self, token):
        try:
            response = _cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id(),
                ClientId=self.user_pool_client_id(),
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'USERNAME': self.id,
                    'REFRESH_TOKEN': token
                },
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise
        if 'ChallengeName' in response and response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
            # Need to set a new password
            raise Exception('Cannot refresh credentials, need to reset password')

        expiry_date = datetime.datetime.now() + datetime.timedelta(seconds=response['AuthenticationResult']['ExpiresIn'])
        return {
            'jwt': response['AuthenticationResult']['IdToken'],
            'access_token': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': token,
        }

    def logout(self):
        try:
            _cognito_client.admin_user_global_sign_out(
                UserPoolId=self.user_pool_id(),
                Username=self.id,
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise

    @classmethod
    def flatten(cls, d, prefix=''):
        """
        Flatten nested dictionaries
        :param dict d:
        :param str prefix:
        :return: dict
        """
        ret = {}
        for key, value in d.items():
            if isinstance(value, dict):
                ret[f'{prefix}{key}'] = json.dumps(value)
            else:
                ret[f'{prefix}{key}'] = str(value)
        # print(f'flatten input={d}, output={ret}')
        return ret

    @classmethod
    def unflatten(cls, d):
        """
        Unflatten nested dictionaries
        :param dict d:
        :return: dict
        """
        ret = {}
        for key, value in d.items():
            if value is None:
                ret[key] = None
            else:
                try:
                    ret[key] = json.loads(value)
                except json.decoder.JSONDecodeError as e:
                    ret[key] = value
        return ret

