"""Exact fixture ownership for the optional two-service maintenance lab worker."""

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from uuid import UUID

from django.core.management.base import CommandError

from apps.infrastructure.node_maintenance_models import NodeMaintenanceDelivery, NodeMaintenanceWindow
from apps.provisioning.service_models import Service
from apps.provisioning.virtualmin_models import VirtualminServer

TICK = "apps.infrastructure.node_maintenance_tasks.tick_node_maintenance"
SEND = "apps.notifications.tasks.send_email_task"
PRIVATE_FILE_MODE = 0o600
MAX_MANIFEST_BYTES = 65536


def read_maintenance_scope(path: Path) -> dict[str, object]:
    """The fixture owner may atomically add its newly created windows to this private manifest."""
    try:
        identity = path.lstat()
        if (
            not stat.S_ISREG(identity.st_mode)
            or stat.S_IMODE(identity.st_mode) != PRIVATE_FILE_MODE
            or identity.st_uid != os.getuid()
            or identity.st_size > MAX_MANIFEST_BYTES
        ):
            raise ValueError("Manifest must be private and bounded")
        scope = json.loads(path.read_text())["scope"]
        if not isinstance(scope, dict):
            raise ValueError("Missing fixture scope")
        return scope
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise CommandError("A private maintenance fixture manifest is required") from error


def _ids(scope: Mapping[str, object], name: str, *, numeric: bool = False) -> set[str]:
    values = scope.get(name)
    if not isinstance(values, list) or not values:
        raise ValueError("Missing fixture identities")
    if numeric:
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("Invalid numeric fixture identity")
    elif any(not isinstance(value, str) or str(UUID(value)) != value for value in values):
        raise ValueError("Invalid UUID fixture identity")
    return {str(value) for value in values}


def _owned_scope(scope: Mapping[str, object]) -> tuple[set[str], set[str], set[str]] | None:
    nodes = _ids(scope, "node_ids")
    customers = _ids(scope, "customer_ids", numeric=True)
    services = _ids(scope, "service_ids", numeric=True)
    windows = _ids(scope, "window_ids")
    actual_nodes = VirtualminServer.objects.filter(pk__in=nodes, node_deployment__isnull=True)
    if {str(pk) for pk in actual_nodes.values_list("pk", flat=True)} != nodes:
        return None
    placed = list(Service.objects.filter(virtualmin_account__server_id__in=nodes).values_list("pk", "customer_id"))
    if {str(pk) for pk, _customer in placed} != services or any(
        str(customer) not in customers for _pk, customer in placed
    ):
        return None
    actual_windows = NodeMaintenanceWindow.objects.filter(pk__in=windows, node_id__in=nodes)
    if {str(pk) for pk in actual_windows.values_list("pk", flat=True)} != windows:
        return None
    if any(
        str(pk) not in services
        for pk in actual_windows.values_list("audience__service_id_snapshot", flat=True)
        if pk is not None
    ):
        return None
    return customers, services, windows


def _email_log_id(args: object, kwargs: object) -> UUID | None:
    if not isinstance(args, (list, tuple)) or not isinstance(kwargs, dict):
        return None
    if len(args) == 1 and not kwargs:
        candidate = args[0]
    elif not args and set(kwargs) == {"email_log_id"}:
        candidate = kwargs["email_log_id"]
    else:
        return None
    return UUID(candidate) if isinstance(candidate, str) else None


def owned_maintenance_task(task: Mapping[str, object], scope: Mapping[str, object]) -> bool:
    """Qualify before touching the broker; unknown functions and foreign work stay queued."""
    try:
        owned = _owned_scope(scope)
        if owned is None:
            return False
        customers, services, windows = owned
        args, kwargs = task.get("args", ()), task.get("kwargs", {})
        if task.get("func") == TICK:
            if (
                not isinstance(args, (list, tuple))
                or args
                or not isinstance(kwargs, dict)
                or set(kwargs) != {"window_ids"}
            ):
                return False
            selected = kwargs["window_ids"]
            return (
                isinstance(selected, list)
                and bool(selected)
                and all(isinstance(value, str) and value in windows for value in selected)
            )
        if task.get("func") == SEND:
            log_id = _email_log_id(args, kwargs)
            if log_id is not None:
                intent = NodeMaintenanceDelivery.objects.filter(
                    email_log_id=log_id,
                    window_id__in=windows,
                    customer_id__in=customers,
                    email_log__customer_id__in=customers,
                    email_log__template_key__startswith="maintenance_",
                ).first()
                return intent is not None and all(str(value) in services for value in intent.selected_service_ids)
    except (TypeError, ValueError, AttributeError):
        return False
    return False
