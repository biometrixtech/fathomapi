import datetime


def format_datetime(date_input):
    """
    Formats a date in ISO8601 short format.
    :param date_input:
    :return: str
    """
    if date_input is None:
        return None
    if not isinstance(date_input, datetime.datetime):
        date_input = datetime.datetime.strptime(date_input, "%Y-%m-%dT%H:%M:%S.%f")
    return date_input.strftime("%Y-%m-%dT%H:%M:%SZ")