"""Registration links that open with a company's details filled in.

Staff mint a link for someone they are onboarding (`manage.py mint_registration_link`): the details
they already have, and optionally the product the customer will order, sealed in an AES-256-GCM
token on the existing keyring, bound to this purpose and valid for 7 days. The portal sends the
token here and fills in the registration form; every field stays editable, and the link proves
nothing about who opens it.

Reading never fails loudly: a token that is too long, tampered with, expired, minted for another
purpose or carrying unknown fields yields nothing.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any

from apps.common.encryption import DecryptionError, decrypt_sensitive_data, encrypt_sensitive_data
from apps.common.intent import clean_intent

PREFILL_AAD = b"praho.registration-prefill.v1"
PREFILL_LIFETIME = timedelta(days=7)
MAX_TOKEN_LENGTH = 4096
# The portal registration form's fields a link may fill in, with their longest values.
FIELD_LIMITS = {
    "email": 254,
    "first_name": 150,
    "last_name": 150,
    "phone": 30,
    "customer_type": 20,
    "company_name": 255,
    "cui": 20,
    "vat_number": 20,
    "trade_registry_number": 50,
    "address_line1": 200,
    "city": 100,
    "county": 100,
    "postal_code": 10,
    "country": 100,
}


def mint_registration_prefill(fields: dict[str, str], intent: dict[str, str] | None = None) -> str:
    """A token carrying fields and intent; ValueError for an unknown field or an over-long value."""
    for name, value in fields.items():
        if name not in FIELD_LIMITS or not isinstance(value, str) or len(value) > FIELD_LIMITS[name]:
            raise ValueError(f"Field {name!r} cannot be prefilled with this value")
    payload = {
        "exp": int(time.time() + PREFILL_LIFETIME.total_seconds()),
        "fields": {name: value for name, value in fields.items() if value},
        "intent": clean_intent(intent or {}),
    }
    return encrypt_sensitive_data(json.dumps(payload, separators=(",", ":")), aad=PREFILL_AAD)


def read_registration_prefill(token: str) -> dict[str, Any]:
    """{"fields": ..., "intent": ...} from a valid unexpired token, else {}."""
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return {}
    try:
        payload = json.loads(decrypt_sensitive_data(token, aad=PREFILL_AAD))
        expires = payload["exp"]
        raw_fields = payload["fields"]
        if not isinstance(expires, int) or expires < time.time() or not isinstance(raw_fields, dict):
            return {}
        if any(
            name not in FIELD_LIMITS or not isinstance(value, str) or len(value) > FIELD_LIMITS[name]
            for name, value in raw_fields.items()
        ):
            return {}
        intent = payload.get("intent") or {}
        return {"fields": dict(raw_fields), "intent": clean_intent(intent if isinstance(intent, dict) else {})}
    except (DecryptionError, ValueError, KeyError, TypeError):
        return {}
