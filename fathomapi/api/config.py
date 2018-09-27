import collections
import os

from ..comms._transport import get_secretsmanager_secret


class Config(collections.Mapping):

    _config = {}

    @classmethod
    def get(cls, key):
        key = str(key).upper()

        # have we loaded it already
        if key in cls._config:
            return cls._config[key]

        # Is it in environment variables
        if key in os.environ:
            return os.environ[key]

        # Can we get it from secrets manager
        cls._config[key] = cls._load_from_secretsmanager(key)
        return cls._config[key]

    @classmethod
    def set(cls, key, value):
        cls._config[key] = value

    @classmethod
    def _load_from_secretsmanager(cls, key):
        secret_name = '/'.join([cls.get('SERVICE'), cls.get('ENVIRONMENT'), key])
        return get_secretsmanager_secret(secret_name)

    def __iter__(self):
        return {k: v for k, v in self._config.items()}

    def __getitem__(self, key):
        return self.get(key)

    def __len__(self):
        return len(self._config)
