"""Record a registrar's answer against the original paid domain line."""

from __future__ import annotations

from datetime import date, datetime, time
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.audit.services import DomainsAuditService

from .currency_terms import domain_fields_from_order_item
from .domain_names import canonicalize_domain_name
from .models import Domain, DomainOperation, DomainOrderItem
from .operation_services import DomainOperationService
from .order_fulfilment import ORDERABLE_DOMAIN_ACTIONS, fail_order_line, fulfil_order_item_for_domain

if TYPE_CHECKING:
    from apps.orders.models import OrderItem
    from apps.users.models import User

MAX_REGISTRY_ID_LENGTH = 100


def _locked_line(order_id: UUID, line_id: UUID) -> tuple[OrderItem, DomainOrderItem, Domain | None]:
    """Caller holds atomic; acquire Order → OrderItem → DomainOrderItem → Domain."""
    from apps.orders.models import Order  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    order = Order.objects.select_for_update(of=("self",)).get(pk=order_id)
    line = order.items.select_for_update(of=("self",)).get(pk=line_id)
    try:
        item = DomainOrderItem.objects.select_for_update(of=("self",)).get(order_item=line)
    except DomainOrderItem.DoesNotExist:
        raise ValueError(_("This line is not a domain registration or transfer.")) from None
    if not line.is_domain_line or item.order_id != order.pk or item.action not in ORDERABLE_DOMAIN_ACTIONS:
        raise ValueError(_("This line is not a domain registration or transfer."))
    if not (
        order.status == "provisioning" or (order.status == "cancelled" and line.provisioning_status == "in_progress")
    ):
        raise ValueError(_("The order is not eligible for recording a registrar answer."))
    domain = Domain.objects.select_for_update().get(pk=item.domain_id) if item.domain_id else None
    if domain is not None and (
        domain.customer_id != order.customer_id
        or domain.name != canonicalize_domain_name(item.domain_name)
        or domain.tld_id != item.tld_id
        or domain.registrar_id != item.registrar_id
    ):
        raise ValueError(_("The linked domain does not match the purchased line."))
    return line, item, domain


def record_paid_domain(
    order_id: UUID, line_id: UUID, *, expires_on: date, registrar_domain_id: str, actor: User
) -> int:
    """Record one paid line, then let activation complete it after the transaction commits."""
    registry_id = registrar_domain_id.strip()
    if expires_on <= timezone.localdate() or not registry_id or len(registry_id) > MAX_REGISTRY_ID_LENGTH:
        raise ValueError(_("Enter a future expiry date and the registrar domain ID."))
    with transaction.atomic():
        line, item, domain = _locked_line(order_id, line_id)
        if line.provisioning_status not in ("pending", "failed", "in_progress"):
            raise ValueError(_("This domain line cannot be completed in its current state."))
        if item.registrar is None:
            raise ValueError(_("The registrar recorded for this purchase is required."))
        if domain is not None and domain.status not in ("pending", "transfer_in", "active"):
            raise ValueError(_("This domain cannot be recorded in its current state."))
        if domain is None:
            if Domain.objects.filter(name=canonicalize_domain_name(item.domain_name)).exists():
                raise ValueError(_("A domain with this name already exists; review its ownership first."))
            domain = Domain.objects.create(
                name=item.domain_name,
                tld=item.tld,
                registrar=item.registrar,
                customer=line.order.customer,
                whois_privacy=item.whois_privacy,
                auto_renew=item.auto_renew,
                **domain_fields_from_order_item(
                    item, customer_id=line.order.customer_id, domain_name=item.domain_name, tld_id=item.tld_id
                ),
            )
            item.domain = domain
        if line.provisioning_status == "failed":
            line.retry_provisioning()
        if line.provisioning_status == "pending":
            line.start_provisioning()
        line.save(update_fields=["provisioning_status", "provisioning_notes", "updated_at"])
        domain.registered_at = domain.registered_at or timezone.now()
        domain.expires_at = timezone.make_aware(datetime.combine(expires_on, time.max))
        domain.registrar_domain_id = registry_id
        if domain.status != "active":
            domain.activate()
        domain.save()
        item.epp_code = ""
        item.save(update_fields=["domain", "epp_code", "updated_at"])
        DomainsAuditService.log_domain_order_event(
            "domain_recorded_by_staff",
            item,
            user=actor,
            description=_("Registrar registration or transfer recorded by staff."),
        )
        domain_id = domain.pk
        transaction.on_commit(lambda: fulfil_order_item_for_domain(domain_id), robust=True)
    return 1


def refuse_paid_domain(order_id: UUID, line_id: UUID, *, actor: User) -> None:
    """Record a definite refusal, leaving confirmed domains and other operation types alone."""
    with transaction.atomic():
        line, item, domain = _locked_line(order_id, line_id)
        if (
            line.provisioning_status != "in_progress"
            or domain is None
            or domain.status not in ("pending", "transfer_in")
        ):
            raise ValueError(_("Only an unconfirmed domain operation in progress can be refused."))
        for operation in DomainOperation.objects.select_for_update().filter(
            domain=domain, state__in=("pending", "submitted")
        ):
            operation.mark_failed(_("Registrar refusal recorded by staff."))
            operation.save(update_fields=["state", "error_message", "updated_at"])
        DomainOperationService.discard_unconfirmed(domain.pk)
        item.epp_code = ""
        item.save(update_fields=["epp_code", "updated_at"])
        if not fail_order_line(item, _("Registrar refusal recorded by staff."), notify_staff=False):
            raise ValueError(_("This domain line cannot be failed in its current state."))
        DomainsAuditService.log_domain_order_event(
            "domain_refusal_recorded_by_staff",
            item,
            user=actor,
            description=_("Registrar refusal recorded by staff."),
        )
