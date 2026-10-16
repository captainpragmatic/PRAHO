"""Proof-of-work bot protection for the portal's public forms (ALTCHA).

The browser solves a PBKDF2 challenge this service signed, in a web worker, and submits the
solution with the form. A solution is accepted once: its challenge's signature is claimed until the
challenge expires, so a replayed copy, or the same solution encoded differently, is refused. The
signing secret is derived from SECRET_KEY, so no other setting holds it.

The protection slows automated submissions; it does not replace the per-IP limits or the uniform
answers that keep registration and password recovery from revealing accounts (ADR-0021).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from altcha import Payload, create_challenge, verify_solution
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _

from apps.common import counters

logger = logging.getLogger(__name__)

ALGORITHM = "PBKDF2/SHA-256"
# A solved challenge is about 700 characters; anything far longer is refused before it is decoded.
MAX_PAYLOAD_LENGTH = 4096
FIELD_NAME = "altcha"
VERIFICATION_FAILED = _("Please confirm that you are not a robot, then submit the form again.")


def enabled() -> bool:
    return bool(getattr(settings, "ALTCHA_ENABLED", False))


def _signing_secret() -> str:
    return salted_hmac("praho.portal.altcha", "challenge-signature", algorithm="sha256").hexdigest()


def new_challenge() -> dict[str, Any]:
    """A signed challenge for the widget, expiring after ALTCHA_EXPIRY_SECONDS."""
    challenge = create_challenge(
        ALGORITHM,
        settings.ALTCHA_COST,
        expires_at=int(time.time()) + settings.ALTCHA_EXPIRY_SECONDS,
        hmac_secret=_signing_secret(),
    )
    return challenge.to_dict()


def accept_solution(payload: str) -> bool:
    """Whether payload solves an unexpired challenge this service signed, never accepted before."""
    if not payload or len(payload) > MAX_PAYLOAD_LENGTH:
        return False
    try:
        # The widget's test mode sends a null challenge, which fails here like any other bad payload.
        parsed = Payload.from_base64(payload)
        expires_at = parsed.challenge.parameters.expires_at
        if not isinstance(expires_at, int) or not verify_solution(parsed, _signing_secret()).verified:
            return False
        signature = str(parsed.challenge.signature)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
    # Keyed by the signature, not the payload's bytes: a re-encoded copy is the same solution.
    return counters.claim(f"altcha:{signature}", max(1, expires_at - int(time.time())), "accepted")


class AltchaFormMixin(forms.BaseForm):
    """Adds the proof-of-work field to a public form while ALTCHA_ENABLED is on.

    The field is checked with the other fields, so a solution is spent even when another field is
    refused; the page shown again fetches a new challenge, which the browser solves on submit.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if enabled():
            # The widget renders its own input with this name; the field only receives it.
            self.fields[FIELD_NAME] = forms.CharField(
                required=True, widget=forms.HiddenInput, error_messages={"required": VERIFICATION_FAILED}
            )

    def clean_altcha(self) -> str:
        payload = str(self.cleaned_data.get(FIELD_NAME, ""))
        if not accept_solution(payload):
            raise ValidationError(VERIFICATION_FAILED)
        return payload
