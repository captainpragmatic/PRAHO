"""
Consolidated management command to set up all scheduled tasks for PRAHO Platform.

This command sets up both Virtualmin provisioning tasks and user security tasks.
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.common.tasks import setup_system_status_scheduled_tasks
from apps.orders.tasks import setup_order_scheduled_tasks
from apps.provisioning.virtualmin_tasks import setup_virtualmin_scheduled_tasks
from apps.users.tasks import setup_user_security_scheduled_tasks


class Command(BaseCommand):
    help = "Set up all scheduled tasks for PRAHO Platform (Virtualmin + User Security + Orders + System Status)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force recreation of existing tasks",
        )
        parser.add_argument(
            "--virtualmin-only",
            action="store_true",
            help="Set up only Virtualmin tasks",
        )
        parser.add_argument(
            "--security-only",
            action="store_true",
            help="Set up only user security tasks",
        )
        parser.add_argument(
            "--orders-only",
            action="store_true",
            help="Set up only order processing tasks",
        )
        parser.add_argument(
            "--status-only",
            action="store_true",
            help="Set up only system status tasks",
        )

    def _validate_options(self, options: dict[str, Any]) -> dict[str, bool]:
        """Validate mutually exclusive command options."""
        virtualmin_only = options.get("virtualmin_only", False)
        security_only = options.get("security_only", False)
        orders_only = options.get("orders_only", False)
        status_only = options.get("status_only", False)

        # Check for mutually exclusive flags
        exclusive_flags = [virtualmin_only, security_only, orders_only, status_only]
        if sum(exclusive_flags) > 1:
            raise CommandError(
                "Cannot specify multiple exclusive flags "
                "(--virtualmin-only, --security-only, --orders-only, --status-only)"
            )

        return {
            "virtualmin_only": virtualmin_only,
            "security_only": security_only,
            "orders_only": orders_only,
            "status_only": status_only,
        }

    def _setup_task_category(
        self, category_name: str, emoji: str, setup_function: Any, results_dict: dict[str, str]
    ) -> None:
        """Set up a category of scheduled tasks and display results."""
        self.stdout.write("")
        self.stdout.write(f"{emoji} Setting up {category_name} tasks...")

        task_results = setup_function()
        results_dict.update({f"{category_name.replace(' ', '_').lower()}_{k}": v for k, v in task_results.items()})

        for task_name, result in task_results.items():
            if result == "already_exists":
                self.stdout.write(
                    self.style.WARNING(
                        f"  - {category_name.replace(' ', '_').lower()}_{task_name}: Task already exists (skipped)"
                    )
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  - {category_name.replace(' ', '_').lower()}_{task_name}: Created successfully"
                    )
                )

    def _print_schedule(self, flags: dict[str, bool], run_all: bool) -> None:
        """Print the complete task schedule overview."""
        self.stdout.write("")
        self.stdout.write("📋 Complete Task Schedule:")

        if run_all or flags["virtualmin_only"]:
            self.stdout.write("")
            self.stdout.write("🔧 Virtualmin Provisioning:")
            self.stdout.write("  - Health Check: Every hour")
            self.stdout.write("  - Statistics Update: Every 6 hours")
            self.stdout.write("  - Retry Failed Jobs: Every 15 minutes")

        if run_all or flags["security_only"]:
            self.stdout.write("")
            self.stdout.write("🛡️ User Security:")
            self.stdout.write("  - 2FA Session Cleanup: Every 30 minutes")
            self.stdout.write("  - Failed Login Rotation: Daily at 2 AM")
            self.stdout.write("  - Suspicious Pattern Audit: Every 6 hours")
            self.stdout.write("  - Password Reset Cleanup: Every hour")

        if run_all or flags["orders_only"]:
            self.stdout.write("")
            self.stdout.write("📦 Order Processing:")
            self.stdout.write("  - Process Pending Orders: Every 5 minutes")
            self.stdout.write("  - Sync Payment Status: Every 15 minutes")
            self.stdout.write("  - Process Recurring Orders: Daily at 1 AM")

        if run_all or flags["status_only"]:
            self.stdout.write("")
            self.stdout.write("🔍 System Status:")
            self.stdout.write("  - System Status Check: Daily at 3 AM")

        self.stdout.write("")
        self.stdout.write("🔧 Start workers: python manage.py qcluster")
        self.stdout.write("📊 Monitor tasks: /admin/django_q/")

    def handle(self, *args: Any, **options: Any) -> None:
        self.stdout.write("🚀 Setting up PRAHO Platform scheduled tasks...")

        # Validate options
        flags = self._validate_options(options)
        all_results: dict[str, str] = {}

        try:
            only_flags = [k for k, v in flags.items() if v]
            run_all = not only_flags

            # Set up Virtualmin tasks
            if run_all or flags["virtualmin_only"]:
                self._setup_task_category("virtualmin", "🔧", setup_virtualmin_scheduled_tasks, all_results)

            # Set up User Security tasks
            if run_all or flags["security_only"]:
                self._setup_task_category("user security", "🛡️", setup_user_security_scheduled_tasks, all_results)

            # Set up Order Processing tasks
            if run_all or flags["orders_only"]:
                self._setup_task_category("order processing", "📦", setup_order_scheduled_tasks, all_results)

            # Set up System Status tasks
            if run_all or flags["status_only"]:
                self._setup_task_category("system status", "🔍", setup_system_status_scheduled_tasks, all_results)

            # Summary header
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("✅ PRAHO Platform scheduled tasks configured!"))

            self._print_schedule(flags, run_all)

            # Count summary
            total_tasks = len(all_results)
            created_tasks = sum(1 for v in all_results.values() if v == "created")
            existing_tasks = total_tasks - created_tasks

            self.stdout.write("")
            self.stdout.write(f"📊 Summary: {created_tasks} new tasks created, {existing_tasks} existing tasks skipped")

        except Exception as e:
            raise CommandError(f"❌ Failed to set up scheduled tasks: {e}") from e
