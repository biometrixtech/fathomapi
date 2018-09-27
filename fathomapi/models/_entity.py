from abc import abstractmethod
from decimal import Decimal
from functools import reduce

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
            if config.get('type', None) == 'object':
                self._load_fields(config, parent=f'{parent}{field}.', parent_required=required)
            else:
                if 'enum' in config:
                    field_type = set(config['enum'])
                elif config['type'] == 'array':
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
                    'default': config.get('default', None)
                }

    @property
    def primary_key(self):
        return self._primary_key

    @staticmethod
    @abstractmethod
    def schema():
        raise NotImplementedError

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
                raise ValueError(f'{field} must be one of {field_type}, not {value}')
            return value
        elif isinstance(field_type, list):
            # TODO validate items
            if not isinstance(value, list):
                raise ValueError(f'{field} must be a list')
            return value
        elif field_type == 'string':
            return str(value)
        elif field_type == 'number':
            return Decimal(str(value))
        elif field_type == 'bool':
            return bool(value)
        elif field_type == "types.json/definitions/macaddress":
            return str(value).upper()
        else:
            raise NotImplementedError("field_type '{}' cannot be cast".format(field_type))

    def validate(self, operation: str, body: dict):
        # Primary key must be complete
        if None in self.primary_key.values():
            raise InvalidSchemaException('Incomplete primary key')

        body = flatten(body)

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

    def get(self):
        if self._attributes is None:
            self._hydrate(self._fetch())
        return unflatten({**self._attributes, **self.primary_key})

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
        raise NotImplementedError()

    @abstractmethod
    def patch(self, body):
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()


def flatten(d, prefix=''):
    """
    Flatten nested dictionaries
    :param dict d:
    :param str prefix:
    :return:
    """
    return (reduce(
        lambda new_d, kv:
        isinstance(kv[1], dict) and
        {**new_d, **flatten(kv[1], f'{prefix}{kv[0]}.')} or
        {**new_d, f'{prefix}{kv[0]}': kv[1]},
        d.items(),
        {}
    ))


def unflatten(d):
    """
    Unflatten nested dictionaries
    :param dict d:
    :return:
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
