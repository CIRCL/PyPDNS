from typing import Any


class PDNSError(Exception):
    pass


class RateLimitError(PDNSError):
    pass


class UnauthorizedError(PDNSError):
    pass


class ForbiddenError(PDNSError):
    pass


class ServerError(PDNSError):
    pass


class PDNSRecordTypeError(PDNSError):

    def __init__(self, field_name: str, expected_field_type: str, field: Any):
        self.message = f'Invalid record. {field_name} must be a {expected_field_type}, got {type(field)} - {field}'
