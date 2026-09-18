"""Bounded JSON uploads for the customer ticket API.

One MiB in total leaves room for base64 and JSON under Django's request limit.
The existing ticket scanner remains authoritative for content and file types.
"""

import base64
import binascii
import mimetypes
from typing import Any

from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.translation import gettext as _
from rest_framework import serializers

from apps.tickets.security import TicketAttachmentSecurityScanner

MIN_PRINTABLE_CHARACTER = 32
MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_BYTES = 1024 * 1024


def decode_attachments(value: Any) -> list[SimpleUploadedFile]:
    """Validate every file before the reply or any stored file is created."""
    if not isinstance(value, list) or len(value) > MAX_ATTACHMENTS:
        raise serializers.ValidationError(_("At most 5 attachments are allowed."))
    files = []
    total = 0
    for item in value:
        if not isinstance(item, dict):
            raise serializers.ValidationError(_("Invalid attachment."))
        name, encoded = item.get("filename"), item.get("content")
        if not isinstance(name, str) or not name or any(ord(char) < MIN_PRINTABLE_CHARACTER for char in name):
            raise serializers.ValidationError(_("Invalid attachment filename."))
        if not isinstance(encoded, str) or len(encoded) > (MAX_ATTACHMENT_BYTES + 2) // 3 * 4:
            raise serializers.ValidationError(_("Attachments must total at most 1 MiB."))
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise serializers.ValidationError(_("Invalid attachment encoding.")) from exc
        total += len(content)
        if not content or total > MAX_ATTACHMENT_BYTES:
            raise serializers.ValidationError(_("Attachments must be nonempty and total at most 1 MiB."))
        uploaded = SimpleUploadedFile(
            name, content, content_type=mimetypes.guess_type(name)[0] or "application/octet-stream"
        )
        safe, reason = TicketAttachmentSecurityScanner().scan_uploaded_file(uploaded, original_filename=name)
        if not safe:
            raise serializers.ValidationError(reason)
        uploaded.seek(0)
        files.append(uploaded)
    return files
