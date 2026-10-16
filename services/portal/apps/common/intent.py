"""What a visitor came to buy, and where they came from: carried from registration to the order.

A registration may carry an intent, the product, billing period and domain the visitor chose on the
operator's site, and every order carries the first-touch attribution: UTM tags and the referring
site. Both arrive from outside, in query strings and headers, so clean_intent keeps only known keys
with valid values. Anything else is dropped, and logged by key only.

Identical in both services (tests/integration/test_cross_service_parity.py).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

INTENT_KEYS = ("product", "period", "domain", "domain_mode", "offer_ref")
ATTRIBUTION_KEYS = ("utm_source", "utm_medium", "utm_campaign", "referrer")
PERIODS = frozenset({"monthly", "semiannual", "annual"})
DOMAIN_MODES = frozenset({"register", "transfer", "external"})

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_DOMAIN = re.compile(r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
_OFFER_REF = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_UTM_MAX = 100
_REFERRER_MAX = 200
_PRODUCT_MAX = 100


def _utm(value: str) -> str | None:
    value = " ".join(value.split())
    return value if value and len(value) <= _UTM_MAX and value.isprintable() else None


def _referrer(value: str) -> str | None:
    """The referring site's origin: the scheme and host, never its path or query."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"http", "https"} or not host:
        return None
    origin = f"{parts.scheme}://{host}"
    return origin if len(origin) <= _REFERRER_MAX else None


def _product(value: str) -> str | None:
    value = value.strip().lower()
    return value if len(value) <= _PRODUCT_MAX and _SLUG.fullmatch(value) else None


def _domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    return value if _DOMAIN.fullmatch(value) else None


def _offer_ref(value: str) -> str | None:
    return value if _OFFER_REF.fullmatch(value) else None


def _one_of(choices: frozenset[str]) -> Callable[[str], str | None]:
    return lambda value: value if value in choices else None


_CLEANERS: dict[str, Callable[[str], str | None]] = {
    "product": _product,
    "period": _one_of(PERIODS),
    "domain": _domain,
    "domain_mode": _one_of(DOMAIN_MODES),
    "offer_ref": _offer_ref,
    "utm_source": _utm,
    "utm_medium": _utm,
    "utm_campaign": _utm,
    "referrer": _referrer,
}


def clean_intent(raw: Mapping[str, object], keys: tuple[str, ...] = INTENT_KEYS + ATTRIBUTION_KEYS) -> dict[str, str]:
    """The known keys of raw with valid values; unknown keys and invalid values are dropped."""
    cleaned: dict[str, str] = {}
    dropped = []
    for key, value in raw.items():
        good = _CLEANERS[key](value) if key in keys and key in _CLEANERS and isinstance(value, str) else None
        if good is None:
            if value not in (None, ""):
                dropped.append(str(key)[:40])
        else:
            cleaned[key] = good
    if dropped:
        logger.info("⚠️ [Intent] Dropped keys: %s", sorted(dropped))
    return cleaned
