"""
Django app configuration for Orders app
"""

from django.apps import AppConfig


class OrdersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.orders"
    verbose_name = "Orders"

    def ready(self) -> None:
        """Import signals when Django starts."""
        from . import signals  # Signal registration

        # Connect cross-app billing signals (Phase B: proforma_payment_received)
        signals._connect_billing_signals()

        from django_q.signals import pre_enqueue

        from .tasks import apply_scheduled_order_task_budget

        pre_enqueue.connect(apply_scheduled_order_task_budget, dispatch_uid="orders-scheduled-task-budget")
