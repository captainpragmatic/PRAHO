"""Exact imported SSH inspection for the operator's component migration preview."""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from apps.infrastructure.ansible_service import AnsibleService

from .component_migration_manifest import MAX_MANIFEST_BYTES, ComponentManifest
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminServer


def collect_source_components(server: VirtualminServer, selection: dict[str, object]) -> ComponentManifest:
    """Read only. Authority, current account identity and operator permissions are checked by the caller."""
    identity = connection_identity(server)
    request = {**selection, "server_uuid": str(server.pk), "connection_identity": identity}
    result = AnsibleService().run_server_playbook(
        server,
        "virtualmin_component.yml",
        {"component_action": "inspect", "component_request": request},
        timeout_seconds=180,
    )
    if result.is_err() or not result.unwrap().success:
        raise ValidationError(
            _("Component inspection failed. Check enrolled SSH access and native source preparation.")
        )
    matches = re.findall(r"PRAHO_COMPONENT_INSPECTION=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_MANIFEST_BYTES * 2:
        raise ValidationError(_("The source returned incomplete or oversized component evidence."))
    try:
        manifest = ComponentManifest.parse(json.loads(base64.b64decode(matches[0], validate=True)))
    except (ValueError, UnicodeError) as error:
        raise ValidationError(_("The source returned invalid component evidence.")) from error
    server.refresh_from_db()
    source = manifest.as_json()["source"]
    if (
        connection_identity(server) != identity
        or source["server_uuid"] != str(server.pk)
        or source["connection_identity"] != identity
        or any(source[key] != selection.get(key) for key in ("domain_id", "domain", "owner"))
    ):
        raise ValidationError(_("The enrolled source connection or native domain changed during inspection."))
    return manifest
