"""
Custom token authentication backend with SHA-256 hashing, expiry, and Bearer support.

Closes ADR-0031 Gaps 2 (expiry), 3 (last_used_at), 5 (hashed storage), 8 (Bearer scheme).
"""

import hashlib
import logging

from django.http import HttpRequest
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.users.models import APIToken, User

logger = logging.getLogger(__name__)

# Both RFC 6750 "Bearer" and DRF-legacy "Token" are accepted.
_ACCEPTED_KEYWORDS = ("bearer", "token")
_EXPECTED_AUTH_PARTS = 2


class HashedTokenAuthentication(BaseAuthentication):  # type: ignore[misc]  # DRF stub types BaseAuthentication as Any
    """
    Authenticate requests via ``Authorization: Bearer <key>`` or ``Token <key>``.

    The raw key is SHA-256 hashed before DB lookup — the database never stores
    the plaintext token.  Expired tokens are rejected.  ``last_used_at`` is
    updated at most every 5 minutes to avoid a DB write per request.
    """

    def authenticate(self, request: HttpRequest) -> tuple[User, APIToken] | None:
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != _EXPECTED_AUTH_PARTS:
            return None

        keyword, raw_key = parts
        if keyword.lower() not in _ACCEPTED_KEYWORDS:
            return None

        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        try:
            token = APIToken.objects.select_related("user").get(key_hash=key_hash)
        except APIToken.DoesNotExist:
            raise AuthenticationFailed("Invalid token.") from None

        if not token.user.is_active:
            raise AuthenticationFailed("User account is disabled.")

        if token.is_expired:
            raise AuthenticationFailed("Token has expired.")

        self._update_last_used(token)

        return (token.user, token)

    def authenticate_header(self, request: HttpRequest) -> str:
        return "Bearer"

    @staticmethod
    def _update_last_used(token: APIToken) -> None:
        """Update ``last_used_at`` only if the stored value is stale (>5 min)."""
        now = timezone.now()
        if token.last_used_at is None or (now - token.last_used_at) >= APIToken.LAST_USED_UPDATE_INTERVAL:
            APIToken.objects.filter(pk=token.pk).update(last_used_at=now)
