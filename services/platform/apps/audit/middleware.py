"""Bind the request to the audit actor context (ADR-0016, ADR-0043)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponseBase

from .actor_context import acting_for_request


class AuditActorMiddleware:
    """Make the request's user the audit actor for everything the request does.

    Placed after ``AuthenticationMiddleware``. The user is read lazily, when a receiver asks,
    so a DRF token or a signed Portal call that settles the identity later is honoured too.
    The binding is undone when the request ends, whatever way it ends.
    """

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[[HttpRequest], Any]) -> None:
        self.get_response = get_response
        self._is_async = iscoroutinefunction(get_response)
        if self._is_async:
            markcoroutinefunction(self)

    def __call__(self, request: HttpRequest) -> HttpResponseBase | Awaitable[HttpResponseBase]:
        if self._is_async:
            return self._acall(request)
        with acting_for_request(request):
            response: HttpResponseBase = self.get_response(request)
            return response

    async def _acall(self, request: HttpRequest) -> HttpResponseBase:
        with acting_for_request(request):
            response: HttpResponseBase = await self.get_response(request)
            return response
