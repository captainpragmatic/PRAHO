"""Stable registrar nameserver intents, prepared before the owning workflow dispatches them."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from apps.common.transactions import is_outside_transaction
from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.infrastructure.dns_zone_gateway import canonical_dns_name

from .gateways import RegistrarGatewayFactory
from .models import Domain, DomainOperation
from .operation_services import DomainOperationService

if TYPE_CHECKING:
    from .gateways import BaseRegistrarGateway

MAX_NAMESERVERS = 8


def _binding(domain: Domain) -> dict[str, str]:
    return {
        "domain_id": str(domain.pk),
        "name": domain.name,
        "customer_id": str(domain.customer_id),
        "registrar_id": str(domain.registrar_id),
    }


def binding_matches(domain: Domain, parameters: dict[str, Any]) -> bool:
    return parameters.get("binding") == _binding(domain)


def _retry_proven(previous: DomainOperation | None, domain: Domain, nameservers: list[str]) -> bool:
    if previous is None:
        return False
    return bool(
        previous.state == "failed"
        and previous.operation_type == "nameserver_update"
        and previous.accepted_at is None
        and previous.review_required_at is None
        and previous.submitted_at is not None
        and previous.registrar_id == domain.registrar_id
        and previous.parameters.get("binding") == _binding(domain)
        and previous.parameters.get("nameservers") == nameservers
        and previous.result.get("known_not_applied") is True
        and previous.result.get("failed_submission_at") == previous.submitted_at.isoformat()
    )


def prepare(
    domain: Domain, nameservers: list[str], *, operation_id: UUID, retry_of: UUID | None = None
) -> Result[DomainOperation, str]:
    try:
        normalized = sorted({canonical_dns_name(value) for value in nameservers})
        if not normalized or len(normalized) > MAX_NAMESERVERS:
            raise ValueError("invalid_nameservers")
    except ValueError:
        return Err("invalid_nameservers")
    with transaction.atomic():
        current = Domain.objects.select_for_update().get(pk=domain.pk)
        parameters: dict[str, Any] = {"nameservers": normalized, "binding": _binding(current)}
        if retry_of is not None:
            rejected = DomainOperation.objects.select_for_update().filter(pk=retry_of, domain=current).first()
            if not _retry_proven(rejected, current, normalized):
                return Err("registrar_failure_requires_review")
            parameters["retry_of"] = str(retry_of)
        previous = DomainOperation.objects.select_for_update().filter(pk=operation_id).first()
        if previous:
            if (
                previous.domain_id != current.pk
                or previous.registrar_id != current.registrar_id
                or previous.operation_type != "nameserver_update"
                or previous.parameters != parameters
            ):
                return Err("registrar_intent_mismatch")
            return Ok(previous)
        if current.status != "active":
            return Err("domain_not_active")
        return Ok(
            DomainOperation.objects.create(
                id=operation_id,
                domain=current,
                registrar=current.registrar,
                operation_type="nameserver_update",
                parameters=parameters,
                intent_key=str(operation_id),
            )
        )


def _claim_resume(operation: DomainOperation) -> Result[tuple[DomainOperation, BaseRegistrarGateway | None], str]:
    with transaction.atomic():
        domain = Domain.objects.select_for_update().select_related("registrar").get(pk=operation.domain_id)
        current = DomainOperation.objects.select_for_update().get(pk=operation.pk)
        if (
            current.operation_type != "nameserver_update"
            or current.parameters.get("binding") != _binding(domain)
            or current.registrar_id != domain.registrar_id
            or domain.status != "active"
        ):
            return Err("registrar_intent_mismatch")
        if current.state in {"submitted", "completed"}:
            return Ok((current, None))
        if current.state != "pending":
            return Err("registrar_intent_not_pending")
        try:
            gateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
        except ValueError:
            return Err("registrar_gateway_unavailable")
        if not DomainOperationService.dispatch(current):
            return Ok((DomainOperation.objects.get(pk=current.pk), None))
        return Ok((current, gateway))


def resume(operation: DomainOperation) -> Result[DomainOperation, str]:
    if not is_outside_transaction():
        return Err("nameserver_update_requires_autocommit")
    claimed = _claim_resume(operation)
    if claimed.is_err():
        return Err(claimed.unwrap_err())
    current, gateway = claimed.unwrap()
    if gateway is None:
        return Ok(current)
    # The pending→submitted evidence above is durably committed before the request escapes.
    with transaction.atomic():
        domain = Domain.objects.select_for_update().get(pk=operation.domain_id)
        current = DomainOperation.objects.select_for_update().get(pk=operation.pk)
        if current.parameters.get("binding") != _binding(domain) or domain.status != "active":
            return Err("registrar_intent_mismatch")
        result = gateway.update_nameservers(domain.name, current.parameters["nameservers"])
        if result.is_ok():
            update = result.unwrap()
            current.accepted_at = timezone.now()
            if update.pending:
                current.registrar_operation_id = update.operation_handle
            else:
                domain.nameservers = current.parameters["nameservers"]
                domain.save(update_fields=["nameservers", "updated_at"])
                current.mark_completed()
            current.save()
            return Ok(current)
        error = result.unwrap_err()
        if retriability_of(result) != Retriability.UNKNOWN:
            current.mark_failed(error.code.value)
            current.result = {
                **current.result,
                "known_not_applied": True,
                "failed_submission_at": current.submitted_at.isoformat() if current.submitted_at else "",
                "retriability": retriability_of(result).value,
            }
        else:
            current.error_message = error.code.value
        current.save()
        return Err(f"Nameserver update failed: {error.code.value}")
