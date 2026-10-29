"""Bounded signed-JSON inputs; customer/provider ownership comes from the request context."""

import base64
import binascii
import re
from typing import Any

from apps.domains.dns_zone_import import MAX_UPLOAD_BYTES

MAX_ENCODED_UPLOAD = 4 * ((MAX_UPLOAD_BYTES + 2) // 3)


def positive_integer(value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("invalid_integer")
    return value


def bounded_text(value: Any, *, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(character in value for character in "\x00\r\n"):
        raise ValueError("invalid_text")
    return value


def upload_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_ENCODED_UPLOAD:
        raise ValueError("invalid_zone_upload")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid_zone_upload") from error
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("zone_upload_limit")
    return raw


def digest_text(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("invalid_digest")
    return value
