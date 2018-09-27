from abc import abstractmethod
from botocore.exceptions import ClientError
import boto3

from ._entity import Entity
from ..utils.exceptions import NoSuchEntityException


iot_client = boto3.client('iot')


class IotEntity(Entity):

    def __init__(self, thing_id):
        super().__init__({'id': thing_id})

    @staticmethod
    def schema():
        raise NotImplementedError

    @property
    @abstractmethod
    def thing_type(self):
        raise NotImplementedError

    @property
    def id(self):
        return self.primary_key['id']

    def _fetch(self):
        try:
            return iot_client.describe_thing(thingName=self.id)['attributes']
        except ClientError as e:
            if 'ResourceNotFound' in str(e):
                raise NoSuchEntityException()
            else:
                raise

    def create(self, body):
        raise NotImplementedError

    def patch(self, body):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError

    @classmethod
    def get_many(cls, key, value):
        things = iot_client.list_things(attributeName=key, attributeValue=value)['things']
        ret = []
        for thing in things:
            obj = cls(thing['thingName'])
            obj._hydrate(thing['attributes'])
            ret.append(obj)
        return ret
