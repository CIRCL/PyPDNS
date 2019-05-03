

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
