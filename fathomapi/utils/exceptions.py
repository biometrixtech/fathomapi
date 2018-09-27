
class ApplicationException(Exception):
    def __init__(self, status_code, status_code_text, message):
        self._status_code = status_code
        self._status_code_text = status_code_text
        self._message = message

    @property
    def status_code(self):
        return self._status_code

    @property
    def status_code_text(self):
        return self._status_code

    @property
    def message(self):
        return self._message


class NoUpdatesException(ApplicationException):
    def __init__(self, message='No updates are to be performed'):
        super().__init__(202, 'NoUpdates', message)


class InvalidSchemaException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(400, 'InvalidSchema', message)


class UnauthorizedException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(401, 'Unauthorized', message)


class ForbiddenException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(403, 'Forbidden', message)


class NoSuchEntityException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(404, 'NoSuchEntity', message)


class ValueNotFoundInDatabase(ApplicationException):
    def __init__(self, message=''):
        super().__init__(404, 'ValueNotFoundInDatabase', message)


class DuplicateEntityException(ApplicationException):
    def __init__(self, message='Duplicate Entity'):
        super().__init__(409, 'DuplicateEntity', message)


class InvalidPasswordFormatException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(422, 'InvalidPasswordFormat', message)


class ImmutableFieldUpdatedException(ApplicationException):
    def __init__(self, message=''):
        super().__init__(422, 'ImmutableFieldUpdated', message)
