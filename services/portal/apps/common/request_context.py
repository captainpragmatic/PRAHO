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
_user_id: ContextVar[object] = ContextVar("portal_session_user_id", default=None)
_interactive: ContextVar[bool] = ContextVar("portal_session_interactive", default=True)
_rejected: ContextVar[bool] = ContextVar("portal_session_rejected", default=False)
# Inside a request scope opened by bound(); bind() outside one would outlive the request.
_scoped: ContextVar[bool] = ContextVar("portal_session_scoped", default=False)


@contextmanager
def bound(session_id: object, user_id: object = None) -> Iterator[None]:
    """Bind one request's session and its user; everything is restored when the request ends."""
    live_id = session_id if isinstance(session_id, str) and session_id and user_id is not None else None
    tokens = (
        _session_id.set(live_id),
        _user_id.set(user_id if live_id is not None else None),
        _interactive.set(True),
        _rejected.set(False),
        _scoped.set(True),
    )
    try:
        yield
    finally:
        _scoped.reset(tokens[4])
        _rejected.reset(tokens[3])
        _interactive.reset(tokens[2])
        _user_id.reset(tokens[1])
        _session_id.reset(tokens[0])


def bind(session_id: str, user_id: object) -> None:
    """Use a session opened during this request (login), for the rest of it; outside one, nothing."""
    if _scoped.get():
        _session_id.set(session_id)
        _user_id.set(user_id)


@contextmanager
def background() -> Iterator[None]:
    """Calls the customer did not make (revalidation): they never extend the idle deadline."""
    token = _interactive.set(False)
    try:
        yield
    finally:
        _interactive.reset(token)


def signed_fields() -> dict[str, object]:
    """What every signed body made inside a signed-in request carries; empty when no session is bound.

    The user too: a call that names only a customer is bound like one that names the user, so no
    Platform endpoint is reached outside the session check.
    """
    session_id = _session_id.get()
    if session_id is None:
        return {}
    return {"user_id": _user_id.get(), "session_id": session_id, "interactive": _interactive.get()}


def mark_rejected() -> None:
    if _session_id.get() is not None:
        _rejected.set(True)


def rejected() -> bool:
    return _rejected.get()


def forget_rejection() -> None:
    """For logout: a session Platform already ended is the outcome logout wanted."""
    _rejected.set(False)
