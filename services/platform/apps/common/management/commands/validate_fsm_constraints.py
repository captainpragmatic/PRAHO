"""
Validate CHECK constraints match FSM STATUS_CHOICES for all FSM-protected models.

Detects drift between:
- Model STATUS_CHOICES (Python — what Django validates)
- DB CHECK constraints (PostgreSQL — what the database enforces)

Run after adding new statuses or modifying FSM transitions to catch mismatches
before they cause migration failures or silent data corruption.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django_fsm import FSMField


# Registry of (model_class, fsm_field_name, constraint_name) tuples.
# Populated lazily in handle() to avoid import-time side effects.
def _get_fsm_registry() -> list[tuple[type, str, str]]:
    from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.metering_models import BillingCycle, UsageAggregation  # noqa: PLC0415
    from apps.billing.payment_models import Payment  # noqa: PLC0415
    from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
    from apps.billing.refund_models import Refund  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.customer_models import Customer  # noqa: PLC0415
    from apps.domains.models import Domain  # noqa: PLC0415
    from apps.orders.models import Order, OrderItem  # noqa: PLC0415
    from apps.promotions.models import PromotionCampaign  # noqa: PLC0415
    from apps.provisioning.relationship_models import ServiceGroup  # noqa: PLC0415
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.tickets.models import Ticket  # noqa: PLC0415

    return [
        (Order, "status", "order_status_valid_values"),
        (OrderItem, "provisioning_status", "orderitem_provisioning_status_valid_values"),
        (Invoice, "status", "invoice_status_valid_values"),
        (ProformaInvoice, "status", "proformainvoice_status_valid_values"),
        (Payment, "status", "payment_status_valid_values"),
        (Refund, "status", "refund_status_valid_values"),
        (Subscription, "status", "subscription_status_valid_values"),
        (Service, "status", "service_status_valid_values"),
        (Domain, "status", "domain_status_valid_values"),
        (Ticket, "status", "ticket_status_valid_values"),
        (Customer, "status", "customer_valid_status"),
        (EFacturaDocument, "status", "efactura_valid_status"),
        (PromotionCampaign, "status", "campaign_valid_status"),
        (BillingCycle, "status", "billingcycle_status_valid_values"),
        (UsageAggregation, "status", "usageaggregation_status_valid_values"),
        (ServiceGroup, "status", "service_group_valid_status"),
    ]


class Command(BaseCommand):
    help = "Validate that DB CHECK constraints match FSM STATUS_CHOICES for all models"

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: C901, PLR0912
        registry = _get_fsm_registry()
        errors: list[str] = []
        checked = 0

        for model_class, field_name, constraint_name in registry:
            checked += 1
            model_label = f"{model_class.__name__}.{field_name}"

            # 1. Verify field is FSMField
            try:
                field = model_class._meta.get_field(field_name)
            except Exception:
                errors.append(f"{model_label}: field not found")
                continue

            if not isinstance(field, FSMField):
                errors.append(f"{model_label}: not an FSMField (is {type(field).__name__})")
                continue

            # 2. Extract STATUS_CHOICES values
            choices = field.choices
            if not choices:
                errors.append(f"{model_label}: FSMField has no choices defined")
                continue
            choice_values = {c[0] for c in choices}

            # 3. Find matching CheckConstraint in Meta.constraints
            constraint_values: set[str] | None = None
            for constraint in getattr(model_class._meta, "constraints", []):
                if getattr(constraint, "name", "") == constraint_name:
                    # Extract values from Q object
                    q_obj = getattr(constraint, "condition", None) or getattr(constraint, "check", None)
                    if q_obj and hasattr(q_obj, "children"):
                        for child in q_obj.children:
                            if isinstance(child, tuple) and child[0].endswith("__in"):
                                constraint_values = set(child[1])
                                break
                    break

            if constraint_values is None:
                errors.append(f"{model_label}: CHECK constraint '{constraint_name}' not found in Meta.constraints")
                continue

            # 4. Compare
            in_choices_not_constraint = choice_values - constraint_values
            in_constraint_not_choices = constraint_values - choice_values

            if in_choices_not_constraint:
                errors.append(
                    f"{model_label}: in STATUS_CHOICES but missing from CHECK constraint: "
                    f"{sorted(in_choices_not_constraint)}"
                )
            if in_constraint_not_choices:
                errors.append(
                    f"{model_label}: in CHECK constraint but missing from STATUS_CHOICES: "
                    f"{sorted(in_constraint_not_choices)}"
                )

            if not in_choices_not_constraint and not in_constraint_not_choices:
                self.stdout.write(f"  ✅ {model_label} ({len(choice_values)} statuses)")

        self.stdout.write("")
        if errors:
            self.stderr.write(f"❌ {len(errors)} mismatch(es) found:")
            for error in errors:
                self.stderr.write(f"  • {error}")
            raise SystemExit(1)

        self.stdout.write(f"✅ All {checked} FSM models validated — CHECK constraints match STATUS_CHOICES")
