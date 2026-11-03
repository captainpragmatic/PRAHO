"""Node VM root, then source, then synchronization state; never joined locking reads."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import SecuritySource

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminServer


def lock_node(server_id: UUID | None) -> VirtualminServer | None:
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415 -- shared node mutex

    if server_id is None:
        return None
    return VirtualminServer.objects.select_for_update().filter(pk=server_id).first()


def lock_source(source_id: UUID) -> SecuritySource | None:
    anchor = SecuritySource.objects.filter(pk=source_id).values("kind", "virtualmin_server_id").first()
    if anchor is None:
        return None
    server = lock_node(anchor["virtualmin_server_id"]) if anchor["kind"] == "node" else None
    source = SecuritySource.objects.select_for_update().filter(pk=source_id).first()
    if source is None:
        return None
    if source.kind != anchor["kind"] or (
        source.virtualmin_server_id != anchor["virtualmin_server_id"] and source.virtualmin_server_id is not None
    ):
        raise ValidationError(_("The source node binding changed during ownership acquisition"))
    if source.kind == "node" and source.virtualmin_server_id is not None:
        if server is None or server.pk != source.virtualmin_server_id:
            raise ValidationError(_("The bound node is unavailable"))
        # Keep the freshly locked VM, never a joined value from before a lock wait.
        source.virtualmin_server = server
    return source
