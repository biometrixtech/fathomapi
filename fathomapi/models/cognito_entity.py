from ._entity import Entity
from abc import abstractmethod
from botocore.exceptions import ClientError, ParamValidationError
import boto3
import datetime
import json

from fathomapi.utils.exceptions import NoSuchEntityException, DuplicateEntityException, InvalidPasswordFormatException, UnauthorizedException


cognito_client = boto3.client('cognito-idp')


class CognitoEntity(Entity):
    _id = None

    @property
    @abstractmethod
    def username(self):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def schema():
        raise NotImplementedError

    @property
    @abstractmethod
    def user_pool_id(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def user_pool_client_id(self):
        raise NotImplementedError

    @property
    def id(self):
        if self._id is None:
            self._fetch()
        return self._id

    def get(self):
        ret = super().get()
        ret['id'] = self._id
        return ret

    def _fetch(self):
        try:
            res = cognito_client.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=self.username,
            )
            self._id = res['Username']
            return {prop['Name'].split(':')[-1]: prop['Value'] for prop in res['UserAttributes']}

        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise

    def patch(self, body):
        self.validate('PATCH', body)
        attributes_to_update = []
        attributes_to_delete = []
        for key in self.get_fields(immutable=False, primary_key=False):
            if key in body:
                if body[key] is None:
                    attributes_to_delete.append('custom:{}'.format(key))
                else:
                    attributes_to_update.append({'Name': 'custom:{}'.format(key), 'Value': str(body[key])})

        if self.exists():
            cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                UserAttributes=attributes_to_update
            )
            cognito_client.admin_delete_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                UserAttributeNames=attributes_to_delete
            )
        else:
            # TODO
            raise NotImplementedError

        return self.get()

    def create(self, body):
        body['updated_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        body['created_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.validate('PUT', body)

        try:
            cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                TemporaryPassword=body['password'],
                UserAttributes=[
                    {'Name': 'custom:{}'.format(key), 'Value': body[key]}
                    for key in self.get_fields(primary_key=False)
                    if key in body and key != 'password'
                ],
                MessageAction='SUPPRESS',
            )

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
                print(json.dumps({'exception': str(e)}))
                raise
        except ParamValidationError:
            raise InvalidPasswordFormatException('Password does not meet security requirements')

    def delete(self):
        try:
            cognito_client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=self.username
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
            response = cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': self.username,
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
            response = cognito_client.admin_respond_to_auth_challenge(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={'USERNAME': self.username, 'NEW_PASSWORD': password},
                Session=response['Session']
            )

        expiry_date = datetime.datetime.now() + datetime.timedelta(seconds=response['AuthenticationResult']['ExpiresIn'])
        return {
            'jwt': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': response['AuthenticationResult']['RefreshToken'],
        }

    def _login_token(self, token):
        try:
            response = cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'USERNAME': self.username,
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
            'jwt': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': token,
        }

    def logout(self):
        try:
            cognito_client.admin_user_global_sign_out(
                UserPoolId=self.user_pool_id,
                Username=self.username,
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise
