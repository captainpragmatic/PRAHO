"""Signed calls the way the portal makes them: with a live portal session that has just confirmed.

Sensitive customer actions need an identity check from the last 300 seconds (ADR-0017 section 6),
and login counts as one. Tests of what those actions do, rather than of the check itself, call them
with a session opened as login opens it:

- ``BoundRequestFactory`` / ``BoundAPIRequestFactory`` for views called directly, binding each
  request as ``PortalServiceHMACMiddleware`` would;
- ``BoundSessionMixin`` before ``HMACTestMixin``, for signed calls through the real middleware.

Either way the session is the one of the user the signed body names, opened once per test.
"""

from __future__ import annotations

import json
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from rest_framework.test import APIRequestFactory

from apps.users import portal_sessions
from apps.users.models import PortalSession, User


def fresh_session(user: User) -> PortalSession:
    """A live session whose identity check is current, as a login leaves it."""
    return portal_sessions.open_session(user)


def _session_of(sessions: dict[str, PortalSession], user_id: object) -> PortalSession | None:
    key = str(user_id)
    if key not in sessions:
        user = User.objects.filter(pk=user_id).first() if key.isdigit() else None
        if user is None:
            return None  # a body naming no real user stays unbound, as the portal would send it
        sessions[key] = fresh_session(user)
    return sessions[key]


class _Binding:
    _sessions: dict[str, PortalSession]

    def _bind(self, request: HttpRequest) -> HttpRequest:
        try:
            body = json.loads(request.body or b"{}")
        except ValueError:
            return request
        user_id = body.get("user_id") if isinstance(body, dict) else None
        row = _session_of(self.__dict__.setdefault("_sessions", {}), user_id) if user_id is not None else None
        if row is not None:
            request.portal_session = row  # type: ignore[attr-defined]  # as bind_request sets it
        return request


class BoundRequestFactory(_Binding, RequestFactory):
    def generic(self, *args: Any, **kwargs: Any) -> HttpRequest:
        return self._bind(super().generic(*args, **kwargs))


class BoundAPIRequestFactory(_Binding, APIRequestFactory):
    def generic(self, *args: Any, **kwargs: Any) -> HttpRequest:
        return self._bind(super().generic(*args, **kwargs))


class BoundSessionMixin:
    """Each signed body that names an existing user carries a fresh session of that user."""

    def portal_post(self, path: str, data: dict[str, Any] | None = None, **extra: Any) -> HttpResponse:
        return super().portal_post(path, self._bound(data), **extra)  # type: ignore[misc]  # HMACTestMixin's

    def portal_get(self, path: str, data: dict[str, Any] | None = None, **extra: Any) -> HttpResponse:
        return super().portal_get(path, self._bound(data), **extra)  # type: ignore[misc]  # HMACTestMixin's

    def _bound(self, data: dict[str, Any] | None) -> dict[str, Any]:
        body = dict(data or {})
        user_id = body.get("user_id")
        if user_id is None or "session_id" in body:
            return body
        row = _session_of(self.__dict__.setdefault("_portal_sessions", {}), user_id)
        if row is not None:
            body["session_id"] = str(row.pk)
        return body
