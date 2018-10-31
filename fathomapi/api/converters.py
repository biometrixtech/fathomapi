from semver import VersionInfo
from werkzeug.routing import BaseConverter, ValidationError
import re
import uuid


class UuidConverter(BaseConverter):
    def to_python(self, value):
        if _validate_uuid(str(value), 4) or _validate_uuid(str(value), 5):
            return value.lower()
        raise ValidationError()

    def to_url(self, value):
        return value

    type_name = 'uuid'


class VersionNumberConverter(BaseConverter):
    def to_python(self, value):
        try:
            if value.lower() == 'latest':
                return 'latest'
            return VersionInfo.parse(value)
        except Exception:
            raise ValidationError('Version number must be a semantic version')

    def to_url(self, value):
        return str(value)


class Mac6AddressConverter(BaseConverter):
    def to_python(self, value):
        value = value.upper()
        if re.match('^([0-9A-F]{2}:){5}[0-9A-F]{2}', value):
            return value
        else:
            raise ValidationError('Version number must be a semantic version')

    def to_url(self, value):
        return str(value)


class Mac4AddressConverter(BaseConverter):
    def to_python(self, value):
        value = value.upper()
        if re.match('^([0-9A-F]{2}:){3}[0-9A-F]{2}', value):
            return value
        else:
            raise ValidationError('Version number must be a semantic version')

    def to_url(self, value):
        return str(value)


def _validate_uuid(uuid_string, version):
    try:
        val = uuid.UUID(uuid_string, version=version)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False
