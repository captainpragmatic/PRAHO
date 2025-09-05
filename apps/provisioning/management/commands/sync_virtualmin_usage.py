"""
Management command to sync Virtualmin account usage data from API.

This command fetches real usage data from Virtualmin API for all accounts,
replacing any existing usage data with actual values from the servers.
"""

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone

from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Sync Virtualmin account usage data from API."""

    help = "Fetch real usage data from Virtualmin API for all accounts"

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command arguments."""
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be updated without making changes",
        )
        parser.add_argument(
            "--server",
            type=str,
            help="Sync only accounts on specific server (by name)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command."""
        dry_run = options["dry_run"]
        server_name = options.get("server")
        
        # Get accounts to sync
        accounts_query = VirtualminAccount.objects.select_related("server")
        if server_name:
            accounts_query = accounts_query.filter(server__name=server_name)
        
        accounts = list(accounts_query)
        
        if not accounts:
            self.stdout.write(
                self.style.WARNING(f"No accounts found{f' on server {server_name}' if server_name else ''}")
            )
            return
        
        self.stdout.write(f"Found {len(accounts)} accounts to sync")
        
        # Initialize service
        provisioning_service = VirtualminProvisioningService()
        
        updated_count = 0
        error_count = 0
        
        for account in accounts:
            try:
                if dry_run:
                    self.stdout.write(
                        f"DRY RUN: Would fetch usage data for {account.domain} "
                        f"(current: {account.current_disk_usage_mb}MB disk, "
                        f"{account.current_bandwidth_usage_mb}MB bandwidth)"
                    )
                    continue
                
                # Fetch actual usage data from Virtualmin API
                gateway = provisioning_service._get_gateway(account.server)
                domain_info_result = gateway.get_domain_info(account.domain)
                
                if domain_info_result.is_ok():
                    domain_info = domain_info_result.unwrap()
                    
                    # Update usage data
                    old_disk = account.current_disk_usage_mb
                    old_bandwidth = account.current_bandwidth_usage_mb
                    
                    account.current_disk_usage_mb = domain_info.get("disk_usage_mb", 0)
                    account.current_bandwidth_usage_mb = domain_info.get("bandwidth_usage_mb", 0)
                    
                    # Update quotas if available
                    if domain_info.get("disk_quota_mb"):
                        account.disk_quota_mb = domain_info["disk_quota_mb"]
                    if domain_info.get("bandwidth_quota_mb"):
                        account.bandwidth_quota_mb = domain_info["bandwidth_quota_mb"]
                    
                    account.last_sync_at = timezone.now()
                    account.save()
                    
                    self.stdout.write(
                        f"✅ {account.domain}: "
                        f"disk {old_disk}MB → {account.current_disk_usage_mb}MB, "
                        f"bandwidth {old_bandwidth}MB → {account.current_bandwidth_usage_mb}MB"
                    )
                    updated_count += 1
                    
                else:
                    error_msg = domain_info_result.unwrap_err()
                    self.stdout.write(
                        self.style.ERROR(f"❌ {account.domain}: {error_msg}")
                    )
                    error_count += 1
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ {account.domain}: Exception - {e!s}")
                )
                error_count += 1
        
        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Sync completed: {updated_count} updated, {error_count} errors"
                )
            )
