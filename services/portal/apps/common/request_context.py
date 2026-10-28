"""The portal session the current request calls Platform for (ADR-0017 section 5).

``PortalAuthenticationMiddleware`` binds it for the whole request, public routes included, and the
API client adds it to every signed body that names a user. Platform refuses an ended session with
``"active": false``; the client records that here, and the middleware ends the browser session
once the view returns, even when the view caught the error.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_session_id: ContextVar[str | None] = ContextVar("portal_session_id", default=None)
_interactive: ContextVar[bool] = ContextVar("portal_session_interactive", default=True)
_rejected: ContextVar[bool] = ContextVar("portal_session_rejected", default=False)


@contextmanager
def bound(session_id: object) -> Iterator[None]:
    """Bind one request's session; everything is restored when the request ends."""
    tokens = (
        _session_id.set(session_id if isinstance(session_id, str) and session_id else None),
        _interactive.set(True),
        _rejected.set(False),
    )
    try:
        yield
    finally:
        _rejected.reset(tokens[2])
        _interactive.reset(tokens[1])
        _session_id.reset(tokens[0])


def bind(session_id: str) -> None:
    """Use a session opened during this request (login), for the rest of it."""
    _session_id.set(session_id)


@contextmanager
def background() -> Iterator[None]:
    """Calls the customer did not make (revalidation): they never extend the idle deadline."""
    token = _interactive.set(False)
    try:
        yield
    finally:
        _interactive.reset(token)


def signed_fields() -> dict[str, object]:
    """What a signed body that names a user carries; empty when no session is bound."""
    session_id = _session_id.get()
    return {} if session_id is None else {"session_id": session_id, "interactive": _interactive.get()}


def mark_rejected() -> None:
    if _session_id.get() is not None:
        _rejected.set(True)


def rejected() -> bool:
    return _rejected.get()


def forget_rejection() -> None:
    """For logout: a session Platform already ended is the outcome logout wanted."""
    _rejected.set(False)
