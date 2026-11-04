"""Read-only permanent-source proof for an unreachable native quota execution.

A failed health check, destroying state, or operator note is never a fence. Only
authoritative absence of the exact original provider VM, using its creating
credential authority, can retire a token without reaching that native host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint

from .hosting_limit_execution_models import HostingLimitExecution
from .hosting_limit_models import ServiceHostingLimits
from .virtualmin_models import VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

_FIELDS = {
    "schema",
    "deployment_id",
    "server_id",
    "provider_id",
    "provider_type",
    "resource_id",
    "correlation_id",
    "token_fingerprint",
    "endpoint",
    "ssh_port",
    "ssh_host_keys",
}


def _endpoint(server: VirtualminServer) -> dict[str, Any]:
    return {
        "hostname": server.hostname,
        "api_port": server.api_port,
        "api_path": server.api_path,
        "api_username": server.api_username,
        "ssh_port": server.ssh_port,
        "use_ssl": server.use_ssl,
        "ssl_verify": server.ssl_verify,
        "ssl_cert_fingerprint": server.ssl_cert_fingerprint,
        "imported_ssh_host_keys": server.imported_ssh_host_keys,
    }


def provider_binding(server: VirtualminServer) -> dict[str, Any]:
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415 -- Cross-app recovery boundary.

    deployment = NodeDeployment.objects.select_related("provider").filter(virtualmin_server_id=server.pk).first()
    if deployment is None or not deployment.external_node_id or not deployment.provider_token_fingerprint:
        return {}
    return {
        "schema": 1,
        "deployment_id": str(deployment.pk),
        "server_id": str(server.pk),
        "provider_id": str(deployment.provider_id),
        "provider_type": deployment.provider.provider_type,
        "resource_id": deployment.external_node_id,
        "correlation_id": str(deployment.correlation_id),
        "token_fingerprint": deployment.provider_token_fingerprint,
        "endpoint": _endpoint(server),
        "ssh_port": deployment.ssh_port,
        "ssh_host_keys": deployment.ssh_host_keys,
    }


def _current_binding(binding: dict[str, Any], server: VirtualminServer) -> NodeDeployment | None:
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415 -- Cross-app recovery boundary.

    if (
        set(binding) != _FIELDS
        or type(binding.get("schema")) is not int
        or binding["schema"] != 1
        or binding.get("server_id") != str(server.pk)
    ):
        return None
    try:
        deployment = NodeDeployment.objects.select_related("provider").filter(pk=binding["deployment_id"]).first()
    except (ValidationError, ValueError, TypeError):
        return None
    if deployment is None or (
        str(deployment.provider_id) != binding["provider_id"]
        or deployment.provider.provider_type != binding["provider_type"]
        or str(deployment.correlation_id) != binding["correlation_id"]
        or deployment.provider_token_fingerprint != binding["token_fingerprint"]
        or deployment.external_node_id not in {"", binding["resource_id"]}
        or deployment.virtualmin_server_id not in {None, server.pk}
        or deployment.ssh_port != binding["ssh_port"]
        or deployment.ssh_host_keys != binding["ssh_host_keys"]
        or _endpoint(server) != binding["endpoint"]
    ):
        return None
    return deployment


def _provider_absent(deployment: NodeDeployment, binding: dict[str, Any]) -> bool:
    from apps.infrastructure.cloud_gateway import (  # noqa: PLC0415
        get_cloud_gateway,
    )
    from apps.infrastructure.provider_config import get_provider_token  # noqa: PLC0415

    if connection.in_atomic_block:
        raise RuntimeError("Provider source-fencing observation requires autocommit.")
    token = get_provider_token(deployment.provider)
    if token.is_err() or provider_token_fingerprint(token.unwrap()) != binding["token_fingerprint"]:
        return False
    client = get_cloud_gateway(binding["provider_type"], token.unwrap()).resource_client()
    # This is exclusively GET. The shared client rejects non-200/non-404 and
    # inconsistent IDs; an unknown result is never promoted to absence.
    return client.read_exact("server", binding["resource_id"]) is None


def resolve_provider_destroyed_quota(  # noqa: PLR0911 -- Each failed source proof keeps the original hold.
    job: VirtualminProvisioningJob,
    *,
    resolved_by: str,
    note: str,
) -> Result[bool, str]:
    from .hosting_limit_execution import (  # noqa: PLC0415 -- Same Account→Servers→Service boundary.
        _lock_context,
        _release,
    )

    if job.operation != "apply_hosting_limits" or job.status != "attention" or not note.strip():
        return Err("Only a quota execution awaiting attention can be reviewed with a reason.")
    execution = HostingLimitExecution.objects.filter(job_id=job.pk).first()
    binding = (job.parameters or {}).get("quota_provider")
    if execution is None or not isinstance(binding, dict) or not binding:
        return Err("Original provider creator provenance is missing; reach and fence the exact original native host.")
    with transaction.atomic():
        account, server, service = _lock_context(execution)
        current = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution.pk)
        if (
            current.phase != "attention"
            or account.server_id != job.server_id
            or current.account_epoch != account.quota_generation
            or current.owner_id != service.customer_id
            or current.job.parameters.get("quota_provider") != binding
            or current.job.status != "attention"
        ):
            return Err("The quota execution or original account ownership changed; retain its hold.")
        deployment = _current_binding(binding, server)
        if deployment is None:
            return Err("The original provider deployment, resource or endpoint authority changed.")
        owner, epoch, service_id = service.customer_id, account.quota_generation, account.service_id
    try:
        if not _provider_absent(deployment, binding):
            return Err(
                "The exact original provider VM is present or its creating credential is unavailable; retain attention."
            )
    except (ValueError, RuntimeError, OSError):
        return Err("Original provider VM absence could not be verified; retain attention.")
    observed_at = timezone.now()
    with transaction.atomic():
        account, server, service = _lock_context(execution)
        current = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution.pk)
        if (
            current.phase != "attention"
            or current.job.status != "attention"
            or account.server_id != job.server_id
            or account.service_id != service_id
            or service.customer_id != owner
            or account.quota_generation != epoch
            or current.job.parameters.get("quota_provider") != binding
            or _current_binding(binding, server) is None
        ):
            return Err("The original source binding changed during the provider observation; retain its hold.")
        current.receipt = {
            "outcome": "provider_source_absent",
            "provider_binding": binding,
            "observed_at": observed_at.isoformat(),
            "native_identity": current.identity,
            "native_token": str(current.job.execution_token),
            "native_epoch": current.account_epoch,
        }
        current.save(update_fields=["receipt", "updated_at"])
        ServiceHostingLimits.objects.filter(service_id=service_id).update(verified_at=None)
        server.status = "disabled"  # fsm-bypass: source is authoritatively absent; never place or enable work there.
        server.save(update_fields=["status", "updated_at"])
        _release(
            current,
            phase="fenced",
            status="failed",
            message=f"Original provider VM absence verified by {resolved_by}: {note}",
        )
    return Ok(True)
