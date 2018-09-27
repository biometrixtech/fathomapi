from utils import validate_uuid4
from werkzeug.routing import BaseConverter, ValidationError


class UuidConverter(BaseConverter):
    def to_python(self, value):
        if validate_uuid4(str(value)):
            return value
        raise ValidationError()

    def to_url(self, value):
        return value

    type_name = 'uuid'
