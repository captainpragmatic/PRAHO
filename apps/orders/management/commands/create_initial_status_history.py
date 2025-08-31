"""
Management command to create initial status history for existing orders.
This fixes the issue where orders created before OrderStatusHistory was implemented
have empty status history sections.
"""

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandParser

from apps.orders.models import Order, OrderStatusHistory


class Command(BaseCommand):
    help = "Create initial status history records for existing orders"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without actually doing it",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        user_model = get_user_model()
        system_user = user_model.objects.filter(is_superuser=True).first()

        # Find orders without any status history
        orders_without_history = Order.objects.filter(status_history__isnull=True).distinct()

        if not orders_without_history.exists():
            self.stdout.write(self.style.SUCCESS("All orders already have status history records."))
            return

        count = orders_without_history.count()

        if options["dry_run"]:
            self.stdout.write(self.style.WARNING(f"DRY RUN: Would create initial status history for {count} orders:"))
            for order in orders_without_history:
                self.stdout.write(f"  - Order {order.order_number} (status: {order.status})")
            return

        created_count = 0
        for order in orders_without_history:
            OrderStatusHistory.objects.create(
                order=order,
                old_status="",  # No previous status for initial record
                new_status=order.status,
                notes=f"Initial status record for existing order {order.order_number}",
                changed_by=system_user,
            )
            created_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"Successfully created initial status history for {created_count} orders.")
        )
