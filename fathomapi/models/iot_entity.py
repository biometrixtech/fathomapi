from abc import abstractmethod
from botocore.exceptions import ClientError
import boto3
import math

from ._entity import Entity
from ..utils.exceptions import NoSuchEntityException


iot_client = boto3.client('iot')


class IotEntity(Entity):

    def __init__(self, thing_id):
        super().__init__({'id': thing_id})

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
    def _get_many(cls, next_token=None, max_items=math.inf, **kwargs):
        args = {'maxResults': min(max_items, 100)}
        if len(kwargs) == 1:
            key, value = next(iter(kwargs.items()))
            args = {'attributeName': key, 'attributeValue': value}
        elif len(kwargs) > 1:
            raise Exception('IoTEntity can only be filtered on one property')

        if next_token is not None:
            args['nextToken'] = next_token

        res = iot_client.list_things(**args)

        count = 0
        for thing in res['things']:
            obj = cls(thing['thingName'])
            obj._hydrate(thing['attributes'])
            yield obj
            count += 1

        next_next_token = res.get('nextToken', None)

        if next_next_token is not None and count < max_items:
            ret = cls.get_many(next_token=next_next_token, max_items=max_items - count, **kwargs)
            yield from ret
            return ret.value

        return next_next_token
