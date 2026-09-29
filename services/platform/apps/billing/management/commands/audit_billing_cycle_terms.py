"""Report proven and held historical terms without changing billing records."""

import json
from typing import Any

from django.core.management.base import BaseCommand

from apps.billing.cycle_provenance import inspect_cycle_provenance
from apps.billing.metering_models import BillingCycle
from apps.billing.subscription_models import SubscriptionItem


class Command(BaseCommand):
    help = "Read-only audit of original billing-cycle and subscription-item currency evidence."

    def handle(self, *args: Any, **options: Any) -> None:
        for cycle in BillingCycle.objects.select_related(
            "subscription", "invoice", "usage_invoice", "proforma"
        ).iterator():
            evidence = inspect_cycle_provenance(cycle)
            self.stdout.write(
                json.dumps(
                    {
                        "cycle_id": str(cycle.pk),
                        "currency": evidence.currency_code,
                        "quantity": evidence.quantity,
                        "unit_price_cents": evidence.unit_price_cents,
                        "state": "held" if evidence.hold_reason else "proven",
                        "hold_reason": evidence.hold_reason,
                        "unrated_tariffs_held": not bool(cycle.pricing_snapshot.get("meters")),
                    }
                )
            )
        for item in SubscriptionItem.objects.filter(currency__isnull=True).iterator():
            self.stdout.write(
                json.dumps(
                    {
                        "subscription_item_id": str(item.pk),
                        "state": "held",
                        "hold_reason": item.currency_hold_reason
                        or "No proven original currency; retain any price protection",
                    }
                )
            )
