"""Audited source enrollment; network reads never run while these transactions are held."""

from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .locks import lock_node, lock_source
from .models import SecuritySource, SecuritySyncState
from .permissions import can_manage_security
from .transport import bind_connection

if TYPE_CHECKING:
    from apps.users.models import User


@dataclass(frozen=True, kw_only=True)
class SourceConfiguration:
    kind: str
    transport: str
    hostname: str
    port: int
    host_keys: str
    installation_id: UUID
    configuration_digest: str
    sync_enabled: bool = False
    virtualmin_server_id: UUID | None = None


def _authorize(actor: User) -> None:
    if not can_manage_security(actor):
        raise PermissionDenied(_("An active security administrator is required."))


def _audit_values(source: SecuritySource) -> dict[str, object]:
    return {
        "installation_id": str(source.installation_id),
        "kind": source.kind,
        "transport": source.transport,
        "hostname": source.hostname,
        "port": source.port,
        "host_keys_sha256": sha256(source.host_keys.encode()).hexdigest(),
        "configuration_digest": source.configuration_digest,
        "generation": source.generation,
        "sync_enabled": source.sync_enabled,
        "retired": source.retired_at is not None,
        "key_identity": source.key_identity,
        "virtualmin_identity": source.virtualmin_identity,
        "virtualmin_server_id": str(source.virtualmin_server_id) if source.virtualmin_server_id else None,
    }


def _audit(source: SecuritySource, actor: User, operation: str, old: dict[str, object] | None = None) -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415 -- audit service boundary

    AuditService.log_simple_event(
        "configuration_changed",
        user=actor,
        content_object=source,
        description="Changed explicit CrowdSec source enrollment",
        old_values=old or {},
        new_values=_audit_values(source),
        metadata={"source_app": "security", "security_operation": operation},
    )


def _apply(source: SecuritySource, config: SourceConfiguration, *, bind: bool = True) -> None:
    if type(config.sync_enabled) is not bool:
        raise ValidationError(_("CrowdSec synchronization requires an explicit boolean."))
    for field in fields(config):
        setattr(source, field.name, getattr(config, field.name))
    source.full_clean()
    if bind:
        bind_connection(source)


@transaction.atomic
def enroll_source(config: SourceConfiguration, actor: User) -> SecuritySource:
    _authorize(actor)
    source = SecuritySource()
    if config.kind == "node":
        source.virtualmin_server = lock_node(config.virtualmin_server_id)
    _apply(source, config)
    source.save()
    SecuritySyncState.objects.create(source=source)
    _audit(source, actor, "enroll")
    return source


@transaction.atomic
def reconfigure_source(source_id: UUID, config: SourceConfiguration, actor: User) -> SecuritySource:
    _authorize(actor)
    source = lock_source(source_id)
    if source is None:
        raise SecuritySource.DoesNotExist
    if source.retired_at is not None or (source.installation_id, source.kind, source.virtualmin_server_id) != (
        config.installation_id,
        config.kind,
        config.virtualmin_server_id,
    ):
        raise ValidationError(_("Retired or replacement installations require a new enrollment."))
    old = _audit_values(source)
    disabling_only = not config.sync_enabled and all(
        getattr(source, field.name) == getattr(config, field.name)
        for field in fields(config)
        if field.name != "sync_enabled"
    )
    _apply(source, config, bind=not disabling_only)
    source.generation += 1
    source.save()
    SecuritySyncState.objects.filter(source=source).update(
        claim_token=None, claim_phase="", lease_until=None, next_run=timezone.now(), outcome="reconfigured"
    )
    _audit(source, actor, "reconfigure", old)
    return source


@transaction.atomic
def retire_source(source_id: UUID, actor: User) -> SecuritySource:
    _authorize(actor)
    source = SecuritySource.objects.select_for_update().get(pk=source_id)
    if source.retired_at is not None:
        return source
    old = _audit_values(source)
    now = timezone.now()
    source.retired_at, source.sync_enabled = now, False
    source.generation += 1
    source.save(update_fields=["retired_at", "sync_enabled", "generation", "updated_at"])
    SecuritySyncState.objects.filter(source=source).update(
        claim_token=None, claim_phase="", lease_until=None, outcome="retired"
    )
    _audit(source, actor, "retire", old)
    return source
