from abc import ABCMeta, abstractmethod
from decimal import Decimal
import json
from uuid import UUID


class Serialisable:
    __metaclass__ = ABCMeta

    @abstractmethod
    def json_serialise(self):
        return json.loads(json.dumps(self.__dict__, default=json_serialise))


def json_serialise(obj):
    """
    JSON serializer for objects not serializable by default json code
    """
    from datetime import datetime
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    if issubclass(type(obj), Serialisable):
        return obj.json_serialise()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode('utf-8')
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError("Type {} is not serializable".format(type(obj).__name__))
