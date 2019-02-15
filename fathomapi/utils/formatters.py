import datetime
from .exceptions import InvalidSchemaException


def format_datetime(date_input):
    """
    Formats a date in ISO8601 short format.
    :param date_input:
    :return: str
    """
    if date_input is None:
        return None
    if not isinstance(date_input, datetime.datetime):
        for format_string in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"]:
            try:
                date_input = datetime.datetime.strptime(date_input, format_string)
                break
            except ValueError:
                continue
        else:
            raise ValueError('Unrecognised datetime format')
    return date_input.strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_datetime(date_input):
    for format_string in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"]:
        try:
            return datetime.datetime.strptime(date_input, format_string)
        except ValueError:
            pass
    raise InvalidSchemaException('date_time must be in ISO8601 format')