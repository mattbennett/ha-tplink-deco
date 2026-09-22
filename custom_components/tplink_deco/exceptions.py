"""TPLink Deco Exceptions"""


class EmptyDataException(Exception):
    """Empty data exception"""


class ForbiddenException(Exception):
    """Forbidden exception"""


class LoginForbiddenException(Exception):
    """Login forbidden exception"""


class LoginInvalidException(Exception):
    """Invalid login exception"""

    def __init__(self, attempts_remaining):
        self.attempts_remaining = attempts_remaining
        super().__init__(
            f"Invalid login credentials. {attempts_remaining} attempts remaining."
        )


class LoginTemporarilyForbiddenException(Exception):
    """Login was rejected with 403 but may succeed again later.

    Deco firmware reports invalid credentials as error_code -5002 on an HTTP 200
    response, so an HTTP 403 on the login endpoint is not a credentials problem and
    must not trigger a reauth flow until it keeps happening.
    """


class TimeoutException(Exception):
    """Timeout exception"""

    def __init__(self, message=""):
        super().__init__(
            "Timeout exception. If you get a lot of these see"
            f" https://github.com/amosyuen/ha-tplink-deco#timeout-error. {message}"
        )


class UnexpectedApiException(Exception):
    """Unexpected API exception"""
