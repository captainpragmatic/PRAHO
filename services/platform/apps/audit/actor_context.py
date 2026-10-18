"""
Who is acting right now (ADR-0016, ADR-0043).

A model signal sees the row that changed, never the person who changed it, so a receiver
that credits ``instance.user`` records the subject of an edit as its author. This module
carries the real actor from the entry point to the receivers in a ContextVar:

- a web or API request binds its ``HttpRequest`` (middleware) and the actor is read lazily,
  so it is whoever ``request.user`` is once DRF has authenticated it, or the user a
  signed Portal call resolved (``record_request_actor``);
- a script, a test or a management command binds a user explicitly with ``acting_as()``;
- a Django-Q task starts with no actor (``clear_actor_for_task``) and a thread pool
  inherits the submitter's through ``copy_context()``.

The module imports nothing from ``services`` or ``models`` so signal modules can use it freely.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from functools import wraps
from typing import Any

from django.http import HttpRequest

logger = logging.getLogger(__name__)

# A bound user, a bound request (resolved lazily), or nothing.
_binding: ContextVar[Any] = ContextVar("audit_actor_binding", default=None)
_task_tokens: ContextVar[tuple[Token[Any], ...]] = ContextVar("audit_actor_task_tokens", default=())

_REQUEST_ACTOR_ATTR = "_audit_actor"


def _is_authenticated(user: Any) -> bool:
    return user is not None and bool(getattr(user, "is_authenticated", False)) and getattr(user, "pk", None) is not None


def _unwrap(request: Any) -> Any:
    """The Django request under a DRF ``Request`` (attribute writes do not proxy)."""
    return getattr(request, "_request", request)


def current_actor() -> Any:
    """The authenticated user acting now, or ``None`` when nobody (or the system) is."""
    bound = _binding.get()
    if bound is None:
        return None
    if not isinstance(bound, HttpRequest):
        return bound
    try:
        user = getattr(bound, _REQUEST_ACTOR_ATTR, None) or getattr(bound, "user", None)
        return user if _is_authenticated(user) else None
    except Exception:
        logger.warning("⚠️ [Audit] Could not resolve the acting user of the request", exc_info=True)
        return None


@contextmanager
def acting_as(user: Any) -> Iterator[None]:
    """Run a block with ``user`` as the actor. Only an authenticated user or ``None`` is accepted."""
    if user is not None and not _is_authenticated(user):
        raise ValueError("acting_as() accepts an authenticated, saved user or None")
    token = _binding.set(user)
    try:
        yield
    finally:
        _binding.reset(token)


@contextmanager
def acting_for_request(request: HttpRequest) -> Iterator[None]:
    """Bind a request; its actor is resolved when a receiver asks, after authentication settles."""
    token = _binding.set(request)
    try:
        yield
    finally:
        _binding.reset(token)


def record_request_actor(request: Any, user: Any) -> None:
    """Note on the request the user a signed (HMAC) call resolved, which never reaches ``request.user``."""
    if _is_authenticated(user):
        setattr(_unwrap(request), _REQUEST_ACTOR_ATTR, user)


def bind_current_actor[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Wrap a deferred callback so it runs as the actor who scheduled it.

    ``transaction.on_commit`` callbacks run after the middleware has reset the actor, so the
    actor is captured here, when the callback is scheduled, and only the actor is restored:
    a full ``copy_context()`` would also carry an open ``audit_mutation_allowed()`` along.
    """
    actor = current_actor()

    @wraps(func)
    def runner(*args: P.args, **kwargs: P.kwargs) -> R:
        with acting_as(actor):
            return func(*args, **kwargs)

    return runner


def clear_actor_for_task(**kwargs: Any) -> None:
    """Django-Q ``pre_execute``: a task acts for nobody, whatever ran before it in this process."""
    if _binding.get() is None:
        return  # a worker process starts clean; there is nothing to restore afterwards
    token = _binding.set(None)
    _task_tokens.set((*_task_tokens.get(), token))


def restore_actor_after_task(**kwargs: Any) -> None:
    """Django-Q ``post_execute``: undo ``clear_actor_for_task`` when it ran in this same context.

    In cluster mode the monitor is another process and has nothing to undo. Synchronous mode
    runs both signals inline, in the caller's context, where the caller's actor comes back.
    """
    tokens = _task_tokens.get()
    if not tokens:
        return
    *rest, token = tokens
    _task_tokens.set(tuple(rest))
    try:
        _binding.reset(token)
    except ValueError:
        _binding.set(None)
