from abc import abstractmethod
from decimal import Decimal
from functools import reduce
import json
import re

from ..utils.exceptions import InvalidSchemaException, NoSuchEntityException, ImmutableFieldUpdatedException


class Entity:

    def __init__(self, primary_key):
        self._primary_key = primary_key
        self._primary_key_fields = list(primary_key.keys())

        self._fields = {}
        self._load_fields(self.schema())

        self._exists = None
        self._attributes = None

    def _load_fields(self, schema, parent='', parent_required=True):
        for field, config in schema['properties'].items():
            required = field in schema.get('required', []) and parent_required
            default = None
            if config.get('type', None) == 'object' and 'properties' in config:
                self._load_fields(config, parent=f'{parent}{field}.', parent_required=required)
            else:
                if 'enum' in config:
                    field_type = set(config['enum'])
                elif config['type'] == 'array':
                    default = []
                    if 'items' in config:
                        if isinstance(config['items'], list):
                            field_type = config['items']
                        else:
                            field_type = [config['items']]
                    else:
                        field_type = []
                else:
                    field_type = config['type']
                self._fields[f'{parent}{field}'] = {
                    'immutable': config.get('readonly', False),
                    'required': field in schema.get('required', []) and required,
                    'primary_key': field in self._primary_key_fields,
                    'type': field_type,
                    'default': config.get('default', default),
                    'pattern': config.get('pattern', None),
                }

    @property
    def primary_key(self):
        return self._primary_key

    @classmethod
    def schema(cls):
        class_name = camel_to_snake(cls.__name__)
        with open(f'schemas/{class_name}.json', 'r') as f:
            return json.load(f)

    def get_fields(self, *, immutable=None, required=None, primary_key=None):
        return [
            k for k, v in self._fields.items()
            if (immutable is None or v['immutable'] == immutable)
            and (required is None or v['required'] == required)
            and (primary_key is None or v['primary_key'] == primary_key)
        ]

    def cast(self, field, value):
        if field not in self._fields:
            raise KeyError(field)

        field_type = self._fields[field]['type']
        if isinstance(field_type, dict) and '$ref' in field_type:
            field_type = field_type['$ref']

        if isinstance(field_type, set):
            if value not in field_type:
                raise ValueError(f"Field '{field}' must be one of {field_type}, not {value}")
            return value
        elif isinstance(field_type, list):
            # TODO validate items
            if not isinstance(value, (list, set)):
                raise ValueError(f"Field '{field}' must be a list, not {type(value)} ({value})")
            return [v for v in list(value) if v != '_empty']
        elif field_type == 'string':
            value = str(value)
            pattern = self._fields[field]['pattern']
            if pattern is not None and not re.match(pattern, value):
                raise ValueError(f"Field '{field}' value ({value}) must match the regular expression /{pattern}/")
            return value
        elif field_type == 'number':
            return Decimal(str(value))
        elif field_type == 'bool':
            return bool(value)
        elif field_type == "types.json/definitions/macaddress":
            return str(value).upper()
        elif field_type == 'object':
            return value
        else:
            raise NotImplementedError(f"field_type '{field_type}' cannot be cast")

    def validate(self, operation: str, body: dict):
        # Primary key must be complete
        if None in self.primary_key.values():
            raise InvalidSchemaException('Incomplete primary key')

        body = self.flatten(body)

        if operation == 'PATCH':
            # Not allowed to modify readonly attributes for PATCH
            for key in self.get_fields(immutable=True, primary_key=False):
                if key in body:
                    raise ImmutableFieldUpdatedException('Cannot modify value of immutable parameter: {}'.format(key))

        else:
            # Required fields must be present for PUT
            for key in self.get_fields(required=True, primary_key=False):
                if key not in body and key not in self.primary_key.keys():
                    raise InvalidSchemaException('Missing required parameter: {}'.format(key))

        for key in self.get_fields(primary_key=False):
            if key in body:
                try:
                    self.cast(key, body[key])
                except ValueError as e:
                    raise InvalidSchemaException(str(e))

    def exists(self):
        if self._exists is None:
            try:
                self.get()
                self._exists = True
            except NoSuchEntityException:
                self._exists = False
        return self._exists

    @classmethod
    def get_many(cls, **kwargs):
        """
        Get many entities
        :return: ReturnValuedGenerator
        """
        return ReturnValuedGenerator(cls._get_many(**kwargs))

    @classmethod
    def _get_many(cls, **kwargs):
        """
        Get many entities
        """
        raise NotImplementedError

    def get(self, include_internal_properties=False):
        if self._attributes is None:
            self._hydrate(self._fetch())

        if include_internal_properties:
            attributes = self._attributes
        else:
            attributes = {k: v for k, v in self._attributes.items() if k[0] != '_'}

        return self.unflatten({**attributes, **self.primary_key})

    def _hydrate(self, fetch_result):
        self._attributes = {}
        for key in self.get_fields(primary_key=False):
            if key in fetch_result:
                self._attributes[key] = self.cast(key, fetch_result[key])
            else:
                self._attributes[key] = self._fields[key]['default']

    @abstractmethod
    def _fetch(self):
        raise NotImplementedError()

    @abstractmethod
    def create(self, body):
        """
        Create a new entity
        :param dict body:
        :return: entity id
        """
        raise NotImplementedError()

    @abstractmethod
    def patch(self, body):
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()

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
                ret.update(cls.flatten(value, f'{prefix}{key}.'))
            else:
                ret[f'{prefix}{key}'] = value
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
            key_parts = key.split(".")
            d2 = ret
            for part in key_parts[:-1]:
                if part not in d2:
                    d2[part] = dict()
                d2 = d2[part]
            d2[key_parts[-1]] = value
        return ret


def camel_to_snake(string):
    """
    Convert a string in lowerCamelCase or UpperCamelCase to snake_case
    :param str string:
    :return str
    """
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', string)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class ReturnValuedGenerator:
    """
    A Generator which has a return value
    """
    def __init__(self, gen):
        self.gen = gen

    def __iter__(self):
        self.value = yield from self.gen
