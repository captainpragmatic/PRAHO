"""Per-portal HMAC credential registry (#277).

The Portal→Platform HMAC middleware historically verified every request with a single
shared ``PLATFORM_API_SECRET`` regardless of the ``X-Portal-Id`` header, and trusted that
header (which keys nonce dedup and rate-limit buckets). A holder of the shared secret could
rotate ``X-Portal-Id`` per request to mint unlimited buckets.

This module resolves the verifying secret(s) by portal id, under an explicit mode:

- ``legacy``  — verify against ``PLATFORM_API_SECRET`` for any well-formed portal id
                (the historical behavior; the registry is ignored).
- ``audit``   — try the registry keyring first; if it does not verify (id unregistered, OR
                registered but signing with a secret not in its keyring), fall back to the
                shared secret and, only if that fallback SUCCEEDS, log a warning naming the
                portal id. The two cases get distinct warnings so the operator knows whether
                to ADD the id or FIX its registration before enforcing. Audit never causes an
                outage; a request that fails both is a plain 401 with no warning (an
                unauthenticated caller cannot flood "would reject" logs).
- ``enforce`` — registry only. An unregistered portal id is rejected; the signature must
                verify against one of that portal's own secrets. No shared-secret fallback.

The registry value is a keyring — ``{portal_id: [secret, ...]}`` — so rotating a portal to a
distinct secret is make-before-break (add the new secret, roll the portal, drop the old),
mirroring ``ENCRYPTION_KEYS=[current, previous]``.

This module imports only the stdlib + ``django.conf`` so it is safe to import from the
middleware and the app-ready startup hook.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Reject anything outside this charset BEFORE the value reaches a cache key (nonce/rate-limit
# keys embed portal_id). fullmatch (not a ``$``-anchored search) so a trailing newline can't
# slip through — Python's ``$`` matches before a final ``\n``.
PORTAL_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
NONCE_CHARSET_RE = re.compile(r"[A-Za-z0-9._-]+")
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")  # lowercase hex sha256 hexdigest

VALID_MODES = ("legacy", "audit", "enforce")
# Cap the keyring: a rotation needs at most current+previous; a bounded loop also bounds the
# per-request verification work and keeps key-position timing differences small.
MAX_KEYRING_SECRETS = 3


def get_mode() -> str:
    """Return the configured PORTAL_HMAC_MODE (default 'legacy')."""
    return str(getattr(settings, "PORTAL_HMAC_MODE", "legacy"))


@lru_cache(maxsize=8)
def _parse(raw: str) -> dict[str, tuple[str, ...]]:
    """Parse a raw JSON credentials string into {portal_id: (secret, ...)}.

    Cached by the raw string so request-time lookups don't re-parse; a different value
    (including an override_settings change in tests) is a distinct cache entry. Raises
    ImproperlyConfigured on any malformed input — a bad registry must fail loudly, never
    silently degrade to an empty (vulnerability-restoring) registry.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(f"PORTAL_HMAC_CREDENTIALS is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ImproperlyConfigured("PORTAL_HMAC_CREDENTIALS must be a JSON object {portal_id: secret | [secrets]}")

    registry: dict[str, tuple[str, ...]] = {}
    for portal_id, raw_secrets in data.items():
        if not isinstance(portal_id, str) or not PORTAL_ID_RE.fullmatch(portal_id):
            raise ImproperlyConfigured(f"PORTAL_HMAC_CREDENTIALS: invalid portal id {portal_id!r}")
        secrets = [raw_secrets] if isinstance(raw_secrets, str) else raw_secrets
        if not isinstance(secrets, list) or not secrets:
            raise ImproperlyConfigured(
                f"PORTAL_HMAC_CREDENTIALS[{portal_id!r}] must be a non-empty secret or list of secrets"
            )
        if len(secrets) > MAX_KEYRING_SECRETS:
            raise ImproperlyConfigured(
                f"PORTAL_HMAC_CREDENTIALS[{portal_id!r}] has more than {MAX_KEYRING_SECRETS} secrets"
            )
        for secret in secrets:
            if not isinstance(secret, str) or not secret:
                raise ImproperlyConfigured(
                    f"PORTAL_HMAC_CREDENTIALS[{portal_id!r}] contains an empty/non-string secret"
                )
        registry[portal_id] = tuple(secrets)
    return registry


def get_registry() -> dict[str, tuple[str, ...]]:
    """Return the parsed portal credential registry ({} when unset)."""
    raw = getattr(settings, "PORTAL_HMAC_CREDENTIALS", None)
    if not raw:
        return {}
    return _parse(raw)


def resolve_secrets(portal_id: str) -> tuple[str, ...] | None:
    """Return the accepted secret keyring for portal_id, or None if unregistered."""
    return get_registry().get(portal_id)


def validate_at_startup() -> None:
    """ADR-0030 startup validation. Raises ImproperlyConfigured on misconfiguration.

    Called from AppConfig.ready(), after apps are loaded.
    """
    mode = get_mode()
    if mode not in VALID_MODES:
        raise ImproperlyConfigured(f"PORTAL_HMAC_MODE must be one of {VALID_MODES}, got {mode!r}")

    registry = get_registry()  # raises on malformed JSON / shape

    if mode == "enforce" and not registry:
        raise ImproperlyConfigured(
            "PORTAL_HMAC_MODE='enforce' requires a non-empty PORTAL_HMAC_CREDENTIALS registry "
            "(otherwise every portal request would be rejected)."
        )
