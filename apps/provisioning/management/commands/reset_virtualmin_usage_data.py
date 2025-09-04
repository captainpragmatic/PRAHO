"""
Management command to reset Virtualmin account usage data.

This command sets all existing accounts' usage data to zero so that the next sync
will fetch real data from the Virtualmin API instead of showing fake generated data.
"""

from django.core.management.base import BaseCommand

from apps.provisioning.virtualmin_models import VirtualminAccount


class Command(BaseCommand):
    """Reset Virtualmin account usage data to zero."""

    help = "Reset all Virtualmin account usage data to zero for fresh API sync"

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be updated without making changes",
        )

    def handle(self, *args, **options):
        """Execute the command."""
        dry_run = options["dry_run"]
        
        # Get all accounts with non-zero usage data
        accounts_to_reset = VirtualminAccount.objects.filter(
            current_disk_usage_mb__gt=0
        ) | VirtualminAccount.objects.filter(
            current_bandwidth_usage_mb__gt=0
        )
        
        account_count = accounts_to_reset.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f"DRY RUN: Would reset usage data for {account_count} accounts")
            )
            for account in accounts_to_reset:
                self.stdout.write(
                    f"  - {account.domain}: "
                    f"disk={account.current_disk_usage_mb}MB -> 0MB, "
                    f"bandwidth={account.current_bandwidth_usage_mb}MB -> 0MB"
                )
            return
        
        if account_count == 0:
            self.stdout.write(self.style.SUCCESS("No accounts found with usage data to reset"))
            return
            
        # Reset usage data
        updated_count = accounts_to_reset.update(
            current_disk_usage_mb=0,
            current_bandwidth_usage_mb=0
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully reset usage data for {updated_count} accounts. "
                f"Run account sync to fetch real API data."
            )
        )