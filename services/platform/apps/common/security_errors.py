"""Typed, string-compatible security refusals for services returning Result[..., str]."""

from __future__ import annotations

from typing import Literal, Self

from django.core.exceptions import ValidationError


class RateLimitFailure(str):
    """Preserve existing string error contracts while carrying HTTP retry metadata."""

    status_code: Literal[429, 503]
    retry_after: int | None

    def __new__(cls, message: str, *, status_code: Literal[429, 503], retry_after: int | None = None) -> Self:
        failure = super().__new__(cls, message)
        failure.status_code = status_code
        failure.retry_after = retry_after
        return failure

    def __getnewargs_ex__(self) -> tuple[tuple[str], dict[str, int | None]]:
        # Pickle and copy rebuild str subclasses through __new__, which needs the keyword metadata
        return (str(self),), {"status_code": self.status_code, "retry_after": self.retry_after}


class RateLimitValidationError(ValidationError):
    """Carry a refusal through the security decorator's validation error handler."""

    def __init__(self, failure: RateLimitFailure) -> None:
        self.failure = failure
        super().__init__(str(failure))

    def __reduce__(self) -> tuple[type[RateLimitValidationError], tuple[RateLimitFailure]]:
        # ValidationError's args are (message, code, params), which this constructor does not take
        return (type(self), (self.failure,))
