"""Bound numeric owner shadow state to the native archive that captured it."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import tarfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

OWNER_SHADOW_KEY = "praho_backup_owner_shadow_v1"
AGING_FIELDS = frozenset({"change", "min", "max", "warn", "inactive", "expire", "flag"})
MAX_OWNER_SHADOW_BYTES = 4096
UNKNOWN_OWNER_AGING = (
    "Archive owner shadow aging is unknown; take a new backup with capture or review owner login expiry"
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate owner shadow aging field")
        result[key] = value
    return result


def decode_owner_shadow(
    fields: Mapping[str, str],
    *,
    domain: str,
    owner: str,
    archive_name: str,
) -> dict[str, str]:
    """Return only aging, with no credentials or unrelated native metadata."""
    encoded = fields.get(OWNER_SHADOW_KEY)
    if not encoded:
        raise ValueError(UNKNOWN_OWNER_AGING)
    try:
        if len(encoded) > MAX_OWNER_SHADOW_BYTES:
            raise ValueError("Oversized owner shadow aging")
        profile = json.loads(base64.b64decode(encoded, validate=True), object_pairs_hook=_unique_object)
        aging = profile["aging"]
    except (ValueError, KeyError, TypeError, binascii.Error) as error:
        raise ValueError("Archive owner shadow aging is malformed") from error
    if isinstance(profile, dict) and "credential_sha256" not in profile:
        raise ValueError(UNKNOWN_OWNER_AGING)
    if (
        not isinstance(profile, dict)
        or set(profile) != {"version", "domain", "owner", "source_domain_id", "archive", "aging", "credential_sha256"}
        or type(profile.get("version")) is not int
        or profile["version"] != 1
        or fields.get("dom") != domain
        or fields.get("user") != owner
        or profile.get("domain") != domain
        or profile.get("owner") != owner
        or re.fullmatch(r"[0-9]{1,30}", str(fields.get("id", ""))) is None
        or profile.get("source_domain_id") != fields.get("id")
        or profile.get("archive") != archive_name
        or not isinstance(profile.get("credential_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", profile["credential_sha256"]) is None
        or not isinstance(aging, dict)
        or set(aging) != AGING_FIELDS
        or aging.get("flag") != ""
        or any(
            not isinstance(value, str) or re.fullmatch(r"(?:|[0-9]{1,10})", value) is None
            for key, value in aging.items()
            if key != "flag"
        )
    ):
        raise ValueError("Archive owner shadow aging has an invalid identity or unsupported value")
    # Keep EXACTLY the held restore's native credential precedence, including
    # lock prefixes. This digest never leaves the private archive/metadata.
    if "backup_encpass" in fields:
        credential = fields["backup_encpass"]
    elif fields.get("disabled") and "disabled_oldpass" in fields:
        credential = fields["disabled_oldpass"]
    else:
        credential = fields.get("enc_pass", "")
    if not credential or not hmac.compare_digest(
        profile["credential_sha256"], hashlib.sha256(credential.encode()).hexdigest()
    ):
        raise ValueError("Archive owner shadow credential changed after aging capture; take a fresh backup")
    return dict(aging)


def read_archive_owner_shadow(archive: Path, *, domain: str, owner: str, archive_name: str) -> dict[str, str]:
    """Inspect one bounded native metadata member, without extracting tenant files."""
    metadata: bytes | None = None
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if path.name != f"{domain}_virtualmin":
                continue
            if (
                metadata is not None
                or not member.isfile()
                or member.size > 1024 * 1024
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ValueError("Archive owner shadow metadata is duplicated or unsafe")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("Archive owner shadow metadata cannot be read")
            metadata = stream.read(1024 * 1024 + 1)
    if metadata is None or len(metadata) > 1024 * 1024 or b"\0" in metadata:
        raise ValueError("Archive owner shadow metadata is absent or oversized")
    fields: dict[str, str] = {}
    for line in metadata.decode().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            raise ValueError("Archive owner shadow metadata contains duplicate fields")
        fields[key] = value
    return decode_owner_shadow(fields, domain=domain, owner=owner, archive_name=archive_name)
