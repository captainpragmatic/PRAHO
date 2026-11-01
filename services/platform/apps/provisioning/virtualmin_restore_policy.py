"""Bound restore scope before any safety backup, target hold or destructive callback."""

from __future__ import annotations

import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_NATIVE_METADATA_BYTES = 1024 * 1024
NATIVE_FEATURE_FIELDS = frozenset(
    {
        *WEB_ONLY_VIRTUALMIN_FEATURES,
        "dns",
        "mail",
        "ftp",
        "spam",
        "virus",
        "webmin",
        "status",
        "postgres",
        "virtualmin-awstats",
        "virtualmin-mailman",
        "virtualmin-dav",
        "virtualmin-sqlite",
    }
)


def _live_source_domain_id(server: VirtualminServer, account: VirtualminAccount) -> str:
    from .virtualmin_gateway import (  # noqa: PLC0415 -- native boundary
        VirtualminConfig,
        VirtualminGateway,
        listing_attribute,
    )
    from .virtualmin_migration_service import (  # noqa: PLC0415 -- shared native listing contract
        list_migration_domains,
    )

    listing = list_migration_domains(VirtualminGateway(VirtualminConfig(server=server)))
    if listing.is_err():
        raise ValidationError(_("The original source domain cannot be verified before rollback."))
    rows = [row for row in listing.unwrap() if row["domain"] == account.domain]
    if len(rows) != 1 or rows[0]["username"] != account.virtualmin_username or rows[0]["enabled"] is None:
        raise ValidationError(_("Source rollback requires the existing domain and its original owner."))
    return str(listing_attribute(rows[0]["attributes"], "ID"))


def prepare_restore_params(  # noqa: PLR0913 -- archive identity, target identity and overwrite consent are separate inputs.
    account: VirtualminAccount,
    server: VirtualminServer,
    archive: Path,
    metadata: Mapping[str, object],
    *,
    source: str,
    force: bool,
) -> dict[str, object]:
    """Re-read capability and inspect before mutation; legacy full-stack rollback is explicit and bounded."""
    current = VirtualminServer.objects.get(pk=server.pk)
    if refusal := restore_destination_refusal(account, current, force=force):
        raise ValidationError(refusal)
    if current.security_state == "acknowledged_source_only":
        validate_source_rollback(
            account, current, metadata, live_domain_id=_live_source_domain_id(current, account), force=force
        )
        return {"domain": account.domain, "source": source, "all-features": "", "only-existing": ""}
    if current.security_state == "unreviewed":
        # destination_refusal already checked the explicit existing-row rollout
        # exception and its enforcement flag. It never admits a new import here.
        return {"domain": account.domain, "source": source, "all-features": ""}
    inspect_web_archive(archive, account.domain, metadata.get("domain_features"))
    return {
        "domain": account.domain,
        "source": source,
        "feature": list(WEB_ONLY_VIRTUALMIN_FEATURES),
        "only-features": "",
    }


def inplace_source_rollback_candidate(account: VirtualminAccount, server: VirtualminServer, *, force: bool) -> bool:
    """Admission exception only; execution still requires the exact live native domain ID."""
    return (
        force
        and server.security_state == "acknowledged_source_only"
        and not server.security_operation
        and VirtualminAccount.objects.filter(pk=account.pk, server_id=server.pk).exists()
    )


def restore_destination_refusal(account: VirtualminAccount, server: VirtualminServer, *, force: bool) -> str | None:
    current = VirtualminServer.objects.get(pk=server.pk)
    refusal = destination_refusal(current)
    if refusal and inplace_source_rollback_candidate(account, current, force=force):
        return None
    return refusal


def validate_source_rollback(
    account: VirtualminAccount,
    server: VirtualminServer,
    metadata: Mapping[str, object],
    *,
    live_domain_id: str,
    force: bool,
) -> None:
    """A source acknowledgment permits restoration of the SAME existing domain only."""
    current = VirtualminServer.objects.get(pk=server.pk)
    if (
        not inplace_source_rollback_candidate(account, current, force=force)
        or re.fullmatch(r"[0-9]{1,30}", live_domain_id) is None
        or metadata.get("virtualmin_domain_id") != live_domain_id
        or str(metadata.get("node_id")) != str(server.pk)
        or str(metadata.get("praho_service_id")) != str(account.service_id)
        or metadata.get("domain") != account.domain
    ):
        raise ValidationError(_("Source rollback must match the original node, account and existing native domain ID."))


def _native_archive_metadata(archive: Path, domain: str) -> bytes:
    """Read one bounded metadata member while refusing unrelated service payloads."""
    metadata: bytes | None = None
    with tarfile.open(archive, "r|gz") as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValidationError(_("Restore archive contains unsafe paths."))
            if not member.isfile():
                if member.isdir() and path.as_posix() in {".", ".backup"}:
                    continue
                raise ValidationError(_("Restore archive contains an unexpected native member."))
            parts = path.parts[1:] if path.parts[:1] == (".backup",) else path.parts
            if len(parts) != 1 or not parts[0].startswith(domain + "_"):
                raise ValidationError(_("Restore archive includes another domain or unknown native layout."))
            suffix = parts[0].removeprefix(domain + "_")
            feature = re.split(r"[_\.\-]", suffix, maxsplit=1)[0]
            if feature not in {*WEB_ONLY_VIRTUALMIN_FEATURES, "virtualmin"}:
                raise ValidationError(_("Archive holds ancillary services; use component-scoped website migration."))
            if suffix == "virtualmin":
                if metadata is not None or member.size > MAX_NATIVE_METADATA_BYTES:
                    raise ValidationError(_("Native restore metadata is duplicated or oversized."))
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValidationError(_("Native restore metadata cannot be inspected."))
                metadata = stream.read(MAX_NATIVE_METADATA_BYTES + 1)
    if metadata is None or len(metadata) > MAX_NATIVE_METADATA_BYTES or b"\0" in metadata:
        raise ValidationError(_("Inspect the backup's missing or invalid native feature metadata before restoring."))
    return metadata


def inspect_web_archive(archive: Path, domain: str, declared_features: object = None) -> tuple[str, ...]:
    """Inspect native metadata and member scope without extracting customer files or logging credentials."""
    metadata = _native_archive_metadata(archive, domain)
    fields: dict[str, str] = {}
    for line in metadata.decode().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            if key in fields:
                raise ValidationError(_("Native restore metadata contains duplicate fields."))
            fields[key] = value
    if fields.get("dom") != domain:
        raise ValidationError(_("Native restore metadata belongs to another domain."))
    native_features = {name for name in NATIVE_FEATURE_FIELDS if fields.get(name) == "1"}
    if not {"unix", "dir", "web"} <= native_features or native_features - set(WEB_ONLY_VIRTUALMIN_FEATURES):
        raise ValidationError(_("Archive enables ancillary or unclassified services; use component-scoped migration."))
    if declared_features is not None and (
        not isinstance(declared_features, list)
        or any(not isinstance(feature, str) for feature in declared_features)
        or len(declared_features) != len(set(declared_features))
        or set(declared_features) != native_features
    ):
        raise ValidationError(_("Backup feature manifest differs from the inspected native archive."))
    return tuple(name for name in WEB_ONLY_VIRTUALMIN_FEATURES if name in native_features)
