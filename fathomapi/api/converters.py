from semver import VersionInfo
from werkzeug.routing import BaseConverter, ValidationError
import uuid


class UuidConverter(BaseConverter):
    def to_python(self, value):
        if _validate_uuid4(str(value)):
            return value
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


def _validate_uuid4(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False
