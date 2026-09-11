"""Durable registration and renewal intents, committed before registrar I/O.

Cache claims reduce duplicate traffic; these rows are the lasting authority. A
submitted request is never automatically replayed, including after a crash.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.db import connection, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .gateways import RegistrarAPIError, RegistrarGatewayFactory
from .gateways.contracts import parse_date
from .models import Domain, DomainOperation

if TYPE_CHECKING:
    from .gateways import BaseRegistrarGateway
    from .services import DomainRegistrationConfig

logger = logging.getLogger(__name__)
RENEWAL_PENDING = "Renewal submitted and awaiting confirmation — do not resubmit."
TRANSACTION_ERROR = "Registrar operations must run outside an enclosing database transaction."


def intent_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_autocommit() -> bool:
    return connection.get_autocommit() and not connection.in_atomic_block


class DomainOperationService:
    @staticmethod
    def request_review(operation: DomainOperation, message: str) -> None:
        """Expose uncertainty in the existing staff audit review queue once."""
        from apps.audit.services import AuditService  # noqa: PLC0415

        operation.review_required_at = operation.review_required_at or timezone.now()
        operation.error_message = operation.error_message or message
        if not operation.result.get("review_notified"):
            AuditService.log_simple_event(
                "domain_operation_review_required",
                content_object=operation,
                description=f"Registrar {operation.operation_type} operation requires review",
                actor_type="system",
                metadata={
                    "requires_review": True,
                    "operation_id": str(operation.pk),
                    "domain_name": operation.domain.name,
                    "operation_type": operation.operation_type,
                },
            )
            operation.result = {**operation.result, "review_notified": True}
        operation.save(update_fields=["review_required_at", "error_message", "result", "updated_at"])

    @staticmethod
    def dispatch(operation: DomainOperation) -> None:
        """Commit the point after which a crash must be treated as uncertain."""
        operation.mark_submitted()
        operation.next_retry_at = timezone.now() + timedelta(minutes=15)
        operation.save()

    @staticmethod
    def record_response(operation: DomainOperation, success: bool, payload: dict[str, Any]) -> None:
        """Never overwrite a completion delivered concurrently by a webhook."""
        with transaction.atomic():
            Domain.objects.select_for_update().get(pk=operation.domain_id)
            locked = DomainOperation.objects.select_for_update().get(pk=operation.pk)
            if success:
                locked.accepted_at = timezone.now()
                locked.registrar_operation_id = payload.get("operation_handle", "")
            elif locked.state == "submitted":
                message = str(payload.get("error", "Registrar outcome unconfirmed"))
                if payload.get("retriability") in (Retriability.NOT_RETRIABLE.value, Retriability.RETRIABLE.value):
                    locked.mark_failed(message)
                else:
                    locked.error_message = message
            locked.save()

    @classmethod
    def register(cls, config: DomainRegistrationConfig) -> Result[Domain, str]:  # noqa: PLR0911  # explicit dispatch outcomes
        from .services import REGISTRATION_PENDING_MESSAGE, DomainRegistrarGateway  # noqa: PLC0415

        if not require_autocommit():
            return Err(TRANSACTION_ERROR)
        try:
            gateway = RegistrarGatewayFactory.create_gateway(config.registrar)
            gateway.validate_registration_data(config.registrant_data)
        except (ValueError, RegistrarAPIError) as exc:
            return Err(str(exc))

        with transaction.atomic():
            domain = Domain.objects.create(
                name=config.domain_name,
                tld=config.tld,
                registrar=config.registrar,
                customer=config.customer,
                whois_privacy=config.whois_privacy,
                auto_renew=config.auto_renew,
            )
            operation = DomainOperation.objects.create(
                domain=domain,
                registrar=config.registrar,
                operation_type="register",
                intent_key=intent_digest("register"),
                parameters={"years": config.years},
            )
            if not gateway.registration_sets_nameservers and config.registrar.default_nameservers:
                DomainOperation.objects.create(
                    domain=domain,
                    registrar=config.registrar,
                    operation_type="nameserver_update",
                    intent_key=intent_digest("registration_nameservers"),
                    parameters={"nameservers": config.registrar.default_nameservers, "after_registration": True},
                )

        # Contact creation has its own crash boundary. Never guess/recreate a CID
        # when the registrar accepted a contact but the response was lost.
        contact_result = cls._prepare_contact(operation, gateway, config.registrant_data)
        if contact_result.is_err():
            return Err(contact_result.unwrap_err())
        data = {**config.registrant_data}
        if contact_result.unwrap():
            data["registrar_contact_id"] = contact_result.unwrap()
        cls.dispatch(operation)
        try:
            success, payload = DomainRegistrarGateway.register_domain(config.registrar, domain.name, config.years, data)
            cls.record_response(operation, success, payload)
        except Exception:
            logger.exception("Could not record registrar response for operation %s", operation.pk)
            return Err(str(REGISTRATION_PENDING_MESSAGE))
        if not success:
            operation.refresh_from_db()
            if operation.state == "failed":
                # Only explicit rejection, never a not-found read, frees the name.
                with transaction.atomic():
                    locked = Domain.objects.select_for_update().get(pk=domain.pk)
                    if locked.status == "pending":
                        locked.delete()
            return Err(str(payload.get("error", "Registration unconfirmed — do not resubmit.")))
        if payload.get("pending") or not payload.get("expires_at"):
            return Err(str(REGISTRATION_PENDING_MESSAGE))
        cls._complete_registration(domain, operation, payload)
        cls.resume_registration_nameservers(domain)
        domain.refresh_from_db()
        return Ok(domain)

    @staticmethod
    def _prepare_contact(
        operation: DomainOperation,
        gateway: BaseRegistrarGateway,
        data: dict[str, Any],
    ) -> Result[str | None, str]:
        if gateway.registration_requires_contact:
            availability = gateway.check_availability(operation.domain.name)
            if availability.is_err() or not availability.unwrap().available:
                operation.mark_failed("Domain availability could not be confirmed")
                operation.save()
                operation.domain.delete()
                return Err("Domain availability could not be confirmed")
            operation.parameters = {**operation.parameters, "contact_dispatched": True}
            operation.save(update_fields=["parameters", "updated_at"])
        result = gateway.prepare_registration_contact(data)
        if result.is_err():
            operation.error_message = str(result.unwrap_err())
            if retriability_of(result) != Retriability.UNKNOWN:
                operation.domain.delete()
                return Err(operation.error_message)
            DomainOperationService.request_review(operation, "Contact creation unconfirmed")
            return Err("Contact creation unconfirmed; review the registration before retrying.")
        if result.unwrap():
            operation.parameters = {**operation.parameters, "registrar_contact_id": result.unwrap()}
            operation.save(update_fields=["parameters", "updated_at"])
        return Ok(result.unwrap())

    @staticmethod
    def _complete_registration(domain: Domain, operation: DomainOperation, payload: dict[str, Any]) -> None:
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=domain.pk)
            op = DomainOperation.objects.select_for_update().get(pk=operation.pk)
            if locked.status == "pending":
                locked.registrar_domain_id = payload.get("registrar_domain_id", "")
                locked.expires_at = payload["expires_at"]
                locked.nameservers = payload.get("nameservers", [])
                if payload.get("epp_code"):
                    locked.set_encrypted_epp_code(payload["epp_code"])
                locked.registered_at = timezone.now()
                locked.activate()
                locked.save()
            if op.state == "submitted" and locked.status == "active":
                op.mark_completed({"expires_at": payload["expires_at"].isoformat()})
                op.save()

    @staticmethod
    def _replay_renewal(operation: DomainOperation, years: int) -> Result[str, str]:
        if operation.parameters.get("years") != years:
            return Err("This renewal intent was already used with a different duration.")
        if operation.state == "completed":
            return Ok("Domain renewed successfully")
        if operation.state == "submitted" and operation.accepted_at:
            return Ok(RENEWAL_PENDING)
        if operation.state in ("pending", "submitted"):
            return Err(RENEWAL_PENDING)
        return Err(operation.error_message or "This renewal intent was rejected; review before creating another.")

    @classmethod
    def renew(cls, domain: Domain, years: int, token: str | None) -> Result[str, str]:  # noqa: PLR0911  # intent/preflight/dispatch outcomes
        from .services import DomainLifecycleService, DomainRegistrarGateway, TLDService  # noqa: PLC0415

        if not require_autocommit():
            return Err(TRANSACTION_ERROR)
        # Tokenless callers retain a stable legacy intent. Staff and paid orders
        # supply a new explicit token for each intentional extension.
        key = intent_digest(f"legacy:{years}" if token is None else f"token:{token}")
        with transaction.atomic():
            domain = Domain.objects.select_for_update(of=("self",)).select_related("tld", "registrar").get(pk=domain.pk)
            existing = DomainOperation.objects.filter(
                domain=domain,
                registrar=domain.registrar,
                operation_type="renew",
                intent_key=key,
            ).first()
            retry_preflight = (
                existing is not None
                and existing.state == "failed"
                and existing.submitted_at is None
                and existing.accepted_at is None
                and existing.review_required_at is None
                and existing.parameters.get("years") == years
            )
            if existing and not retry_preflight:
                return cls._replay_renewal(existing, years)
            error = DomainLifecycleService._validate_renewal_preconditions(
                domain
            ) or TLDService.validate_renewal_period(domain.tld, years)
            if error:
                return Err(error)
            if DomainOperation.objects.filter(
                domain=domain,
                operation_type="renew",
                state__in=("pending", "submitted"),
            ).exists():
                return Err("Another renewal is awaiting confirmation. Review and retry this item after it completes.")
            if existing:
                operation = DomainOperation.objects.select_for_update().get(pk=existing.pk)
                operation.retry_preflight()
                operation.save()
            else:
                operation = DomainOperation.objects.create(
                    domain=domain,
                    registrar=domain.registrar,
                    operation_type="renew",
                    intent_key=key,
                    parameters={"years": years},
                )
        # A fresh registrar snapshot prevents local drift from becoming false proof
        # of renewal. The pending intent serializes this read with other renewals.
        info_result = DomainRegistrarGateway.get_domain_info(domain.registrar, domain.name)
        if info_result.is_err() or info_result.unwrap().expires_at is None or info_result.unwrap().status != "active":
            operation.mark_failed("Cannot confirm the registrar expiry before renewal; no renewal was sent.")
            operation.save()
            return Err(operation.error_message)
        previous = info_result.unwrap().expires_at
        if previous is None:
            return Err("Registrar expiry is unavailable; no renewal was sent.")
        consumed_expiries = (
            parse_date(result.get("new_expires_at"))
            for result in DomainOperation.objects.filter(
                domain=domain, operation_type="renew", state="completed"
            ).values_list("result", flat=True)
        )
        if any(consumed is not None and previous < consumed for consumed in consumed_expiries):
            operation.mark_failed("Registrar expiry is older than the last confirmed renewal; no renewal was sent.")
            operation.save()
            return Err(operation.error_message)
        operation.parameters = {"years": years, "prev_expires_at": previous.isoformat()}
        cls.dispatch(operation)
        try:
            success, payload = DomainRegistrarGateway.renew_domain(
                domain.registrar, domain, years, idempotency_token=key
            )
            cls.record_response(operation, success, payload)
            if (
                success
                and not payload.get("pending")
                and payload.get("new_expires_at")
                and cls.confirm_renewal(operation, payload["new_expires_at"])
            ):
                return Ok("Domain renewed successfully")
        except Exception:
            logger.exception("Could not record renewal response for operation %s", operation.pk)
            return Err(RENEWAL_PENDING)
        if not success:
            return Err(str(payload.get("error", RENEWAL_PENDING)))
        return Ok(RENEWAL_PENDING)

    @staticmethod
    def confirm_renewal(operation: DomainOperation, expiry: datetime) -> bool:
        with transaction.atomic():
            domain = Domain.objects.select_for_update().get(pk=operation.domain_id)
            op = DomainOperation.objects.select_for_update().get(pk=operation.pk)
            if op.state == "completed":
                return True
            previous = parse_date(op.parameters.get("prev_expires_at"))
            if op.state != "submitted" or previous is None or expiry <= previous:
                return False
            other_renewals = DomainOperation.objects.filter(domain=domain, operation_type="renew").exclude(pk=op.pk)
            # Old concurrent submissions cannot be attributed from a single expiry
            # read. Preserve them for review; do not allocate one extension twice.
            ambiguous = other_renewals.filter(state="submitted").exists()
            for completed in other_renewals.filter(state="completed"):
                consumed = parse_date(completed.result.get("new_expires_at"))
                if consumed is not None and previous < consumed:
                    ambiguous = True
            if ambiguous:
                DomainOperationService.request_review(
                    op, "Renewal confirmation overlaps another intent; registrar review required."
                )
                return False
            if domain.expires_at is None or domain.expires_at < expiry:
                domain.expires_at = expiry
                domain.renewal_notices_sent = 0
                domain.save(update_fields=["expires_at", "renewal_notices_sent", "updated_at"])
            op.mark_completed({"new_expires_at": expiry.isoformat()})
            op.save()
            return True

    @classmethod
    def resume_registration_nameservers(cls, domain: Domain) -> None:
        """Resume only a never-dispatched setup step, never registration itself."""
        if not require_autocommit():
            return
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=domain.pk)
            if locked.status != "active":
                return
            op = (
                DomainOperation.objects.select_for_update()
                .filter(
                    domain=locked,
                    operation_type="nameserver_update",
                    state="pending",
                    parameters__after_registration=True,
                )
                .first()
            )
            if op is None:
                return
            gateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
            if gateway._verified_adapter_guard():
                return
            cls.dispatch(op)
        result = gateway.update_nameservers(domain.name, op.parameters["nameservers"])
        payload: dict[str, Any] = {}
        if result.is_ok():
            payload = {"operation_handle": result.unwrap().operation_handle}
        else:
            payload = {"error": result.unwrap_err().code.value, "retriability": retriability_of(result).value}
        cls.record_response(op, result.is_ok(), payload)
        if result.is_ok() and not result.unwrap().pending:
            with transaction.atomic():
                locked = Domain.objects.select_for_update().get(pk=domain.pk)
                op = DomainOperation.objects.select_for_update().get(pk=op.pk)
                if op.state == "submitted":
                    locked.nameservers = result.unwrap().nameservers
                    locked.save(update_fields=["nameservers", "updated_at"])
                    op.mark_completed()
                    op.save()
