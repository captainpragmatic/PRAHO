"""Bounded recovery of original, pre-envelope email tasks.

Old sweeps lost message fields and their retries filled those fields with defaults.
Only complete original calls (without an explicit retry_count) can be imported.
Additional recipients are held: their erasure may have missed the old row entirely.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from email.utils import parseaddr
from typing import TYPE_CHECKING, TypedDict, cast

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone

from apps.common.encryption import DecryptionError
from apps.common.model_secrets import decrypt_model_secret

if TYPE_CHECKING:
    from apps.notifications.models import EmailLog

logger = logging.getLogger(__name__)

Attachment = tuple[str, bytes, str]
_ATTACHMENT_PARTS = 3
_FIELDS = (
    "to",
    "subject",
    "body_text",
    "body_html",
    "from_email",
    "reply_to",
    "cc",
    "bcc",
    "attachments",
    "tags",
    "track_opens",
    "track_clicks",
    "retry_count",
)


class LegacyEmailRecoveryRequiredError(RuntimeError):
    """Raise OUTSIDE the provider handler so Django-Q retains the original package."""

    def __init__(self) -> None:
        super().__init__("Legacy email requires recovery")


class DeliveryEnvelope(TypedDict):
    """Validated fields required to rebuild a stored message for delivery."""

    to: list[str]
    cc: list[str]
    bcc: list[str]
    tags: dict[str, str]


def delivery_envelope(row: EmailLog) -> DeliveryEnvelope:
    """Read a send envelope without the historical getter's first-recipient fallback."""
    try:
        data = json.loads(decrypt_model_secret(row, "envelope", row.envelope or ""))
        if not isinstance(data, dict) or not data.get("to"):
            raise ValueError
        for key in ("to", "cc", "bcc"):
            addresses = data.get(key, [])
            if not isinstance(addresses, list):
                raise ValueError
            for address in addresses:
                if not isinstance(address, str):
                    raise ValueError
                validate_email(parseaddr(address)[1])
        tags = data.get("tags", {})
        if not isinstance(tags, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in tags.items()):
            raise ValueError
    except (ValueError, TypeError, ValidationError):
        raise DecryptionError("Stored email envelope is invalid") from None
    for key, default in (("cc", []), ("bcc", []), ("tags", {})):
        data.setdefault(key, default)
    return cast("DeliveryEnvelope", data)


def _prepare(row: EmailLog, args: tuple[object, ...], kwargs: dict[str, object]) -> list[Attachment]:
    if row.attachment_refs.exists() or (row.meta or {}).get("attachments_unrecoverable"):
        raise LegacyEmailRecoveryRequiredError
    if len(args) > len(_FIELDS) or set(_FIELDS[: len(args)]) & kwargs.keys():
        raise LegacyEmailRecoveryRequiredError
    supplied = dict(zip(_FIELDS, args, strict=False)) | kwargs
    if set(supplied) - {*_FIELDS, "schedule"} or "retry_count" in supplied or not set(_FIELDS[:-1]) <= supplied.keys():
        raise LegacyEmailRecoveryRequiredError
    if "schedule" in supplied and (
        not isinstance(supplied["schedule"], timedelta) or supplied["schedule"] < timedelta(0)
    ):
        raise LegacyEmailRecoveryRequiredError
    if supplied["to"] != [row.to_addr] or supplied["cc"] not in (None, []) or supplied["bcc"] not in (None, []):
        raise LegacyEmailRecoveryRequiredError
    if (
        supplied["subject"] != row.subject
        or supplied["body_text"] != row.get_decrypted_body_text()
        or (supplied["body_html"] or "") != row.get_decrypted_body_html()
        or supplied["from_email"] != row.from_addr
        or (supplied["reply_to"] or "") != row.reply_to
        or not isinstance(supplied["track_opens"], bool)
        or not isinstance(supplied["track_clicks"], bool)
    ):
        raise LegacyEmailRecoveryRequiredError
    tags = supplied["tags"]
    if tags is not None and (
        not isinstance(tags, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in tags.items())
    ):
        raise LegacyEmailRecoveryRequiredError
    raw = supplied["attachments"]
    if raw is not None and not isinstance(raw, list):
        raise LegacyEmailRecoveryRequiredError
    parts: list[Attachment] = []
    for part in raw or []:
        if (
            not isinstance(part, tuple)
            or len(part) != _ATTACHMENT_PARTS
            or not isinstance(part[0], str)
            or not part[0]
            or not isinstance(part[1], bytes)
            or not isinstance(part[2], str)
            or not part[2]
        ):
            raise LegacyEmailRecoveryRequiredError
        parts.append(part)
    # A historical display-name primary may have escaped erasure before recipient digests existed.
    if parseaddr(row.to_addr)[1] != row.to_addr:
        raise LegacyEmailRecoveryRequiredError
    validate_email(row.to_addr)
    row.envelope = json.dumps({"to": [row.to_addr], "cc": [], "bcc": [], "tags": tags or {}})
    row.meta = {
        **(row.meta or {}),
        "track_opens": supplied["track_opens"],
        "track_clicks": supplied["track_clicks"],
        **({"attachments_unrecoverable": True} if parts else {}),
    }
    row.save(update_fields=["envelope", "meta"])
    return parts


def claim_email_task(
    email_log_id: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> tuple[EmailLog | None, dict[str, object] | None, list[Attachment] | None]:
    """Prepare and claim under one row lock; no raw-byte override survives this call's claim.

    Any preparation failure rolls back and raises a fixed exception. A successful
    error dictionary would acknowledge the only complete broker payload instead.
    """
    from apps.notifications.delivery import (  # noqa: PLC0415  # Circular: delivery uses the hold type
        claim_delivery,
        claimable,
    )
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # Deferred app registry

    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        parts = None
        if row is not None and not row.envelope:
            response = row.provider_response if isinstance(row.provider_response, dict) else {}
            terminal = (
                row.status in {"sent", "delivered", "bounced", "complained", "soft_bounced", "rejected"}
                or response.get("permanent_failure")
                or response.get("retry_exhausted")
                or response.get("erased")
                or (row.meta or {}).get("erased")
            )
            if terminal:
                return row, {"success": False, "error": "Legacy message is terminal", "retry_scheduled": False}, None
            if row.status != "queued" or not claimable(row, timezone.now()):
                logger.warning("⚠️ [Email] Legacy message %s held: not due or uncertain send", row.pk)
                raise LegacyEmailRecoveryRequiredError
            try:
                parts = _prepare(row, args, kwargs)
            except Exception as error:
                # Includes missing encryption keys and DB failures before preparation commits.
                # No original error text or context (which may contain the payload) escapes.
                logger.warning("⚠️ [Email] Legacy message %s held: %s", row.pk, type(error).__name__)
                raise LegacyEmailRecoveryRequiredError from None
        claimed, refusal = claim_delivery(email_log_id)
        return claimed, refusal, parts
