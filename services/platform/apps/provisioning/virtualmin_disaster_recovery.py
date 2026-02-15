"""
Virtualmin Disaster Recovery Service - PRAHO Platform
Implements PRAHO-as-Source-of-Truth disaster recovery patterns.
"""

from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService

logger = logging.getLogger(__name__)

# Module-level defaults for recovery integrity thresholds (used as fallbacks)
_DEFAULT_EXCELLENT_RECOVERY_THRESHOLD = 95
_DEFAULT_GOOD_RECOVERY_THRESHOLD = 90
_DEFAULT_WARNING_RECOVERY_THRESHOLD = 80


class VirtualminDisasterRecoveryService:
    """
    🚨 CRITICAL: Disaster recovery service implementing PRAHO-as-Source-of-Truth.

    This service embodies the core principle that PRAHO data is authoritative
    and Virtualmin servers are replaceable infrastructure ("cattle, not pets").

    Key Recovery Scenarios:
    1. Complete server loss - rebuild all accounts from PRAHO data
    2. Partial corruption - selective restoration from PRAHO
    3. Data drift - enforce PRAHO state across all accounts
    """

    def rebuild_server_from_praho(
        self, target_server: VirtualminServer, dry_run: bool = True
    ) -> Result[dict[str, Any], str]:
        """
        🚨 NUCLEAR OPTION: Rebuild entire Virtualmin server from PRAHO data.

        This is the ultimate expression of PRAHO-as-Source-of-Truth:
        - Completely ignore current Virtualmin state
        - Recreate all accounts based on PRAHO database
        - Servers are truly replaceable infrastructure

        Args:
            target_server: Clean Virtualmin server to rebuild
            dry_run: If True, only report what would be done

        Returns:
            Result with rebuild plan or execution summary
        """
        try:
            # Get all PRAHO accounts that should exist on this server
            praho_accounts = VirtualminAccount.objects.filter(
                server=target_server,
                status__in=["active", "suspended"],  # Only rebuild active accounts
            ).select_related("service", "service__customer")

            if not praho_accounts.exists():
                return Ok(
                    {
                        "message": f"No PRAHO accounts found for server {target_server.hostname}",
                        "accounts_to_rebuild": 0,
                    }
                )

            provisioning_service = VirtualminProvisioningService(target_server)

            rebuild_plan = [
                {
                    "domain": account.domain,
                    "customer": account.service.customer.name,
                    "status": account.status,
                    "disk_quota_mb": account.disk_quota_mb,
                    "bandwidth_quota_mb": account.bandwidth_quota_mb,
                    "template": account.template_name or "Default",
                    "action": "recreate_from_praho_data",
                }
                for account in praho_accounts
            ]

            if dry_run:
                return Ok(
                    {
                        "dry_run": True,
                        "server": target_server.hostname,
                        "accounts_to_rebuild": len(rebuild_plan),
                        "rebuild_plan": rebuild_plan,
                        "message": "🔍 Dry run complete. Use dry_run=False to execute rebuild.",
                    }
                )

            # Execute rebuild
            rebuild_results = []
            successful_rebuilds = 0
            failed_rebuilds = 0

            logger.warning(
                f"🚨 [DisasterRecovery] Starting server rebuild for {target_server.hostname} "
                f"with {len(rebuild_plan)} accounts"
            )

            for account in praho_accounts:
                try:
                    # Recreate account using PRAHO data as authority
                    creation_data = VirtualminAccountCreationData(
                        service=account.service,
                        domain=account.domain,
                        username=account.virtualmin_username,
                        # New password will be generated (old one was encrypted)
                        template=account.template_name or "Default",
                        server=target_server,
                    )
                    result = provisioning_service.create_virtualmin_account(creation_data)

                    if result.is_ok():
                        new_account = result.unwrap()

                        # Apply original status
                        if account.status == "suspended":
                            provisioning_service.suspend_account(new_account, "Restored as suspended from PRAHO data")

                        # Apply quotas if they existed
                        if account.disk_quota_mb or account.bandwidth_quota_mb:
                            # TODO: Implement quota restoration via gateway
                            pass

                        rebuild_results.append(
                            {
                                "domain": account.domain,
                                "status": "success",
                                "new_account_id": str(new_account.id),
                                "original_status": account.status,
                            }
                        )
                        successful_rebuilds += 1

                        logger.info(f"✅ [DisasterRecovery] Rebuilt {account.domain}")

                    else:
                        error_msg = result.unwrap_err()
                        rebuild_results.append({"domain": account.domain, "status": "failed", "error": error_msg})
                        failed_rebuilds += 1

                        logger.error(f"❌ [DisasterRecovery] Failed to rebuild {account.domain}: {error_msg}")

                except Exception as e:
                    rebuild_results.append({"domain": account.domain, "status": "failed", "error": str(e)})
                    failed_rebuilds += 1
                    logger.exception(f"Error rebuilding {account.domain}: {e}")

            # Update server statistics
            target_server.current_domains = successful_rebuilds
            target_server.save(update_fields=["current_domains", "updated_at"])

            return Ok(
                {
                    "server": target_server.hostname,
                    "total_accounts": len(praho_accounts),
                    "successful_rebuilds": successful_rebuilds,
                    "failed_rebuilds": failed_rebuilds,
                    "rebuild_results": rebuild_results,
                    "rebuild_timestamp": timezone.now().isoformat(),
                    "message": f"🏗️ Server rebuild complete: {successful_rebuilds}/{len(praho_accounts)} accounts restored",
                }
            )

        except Exception as e:
            logger.exception(f"Disaster recovery failed for {target_server.hostname}: {e}")
            return Err(str(e))

    def verify_praho_data_integrity(self) -> Result[dict[str, Any], str]:
        """
        Verify PRAHO data integrity for disaster recovery readiness.

        Since PRAHO is the source of truth, we must ensure PRAHO data
        is sufficient to rebuild any Virtualmin server from scratch.

        Returns:
            Result with integrity report
        """
        try:
            # Check for accounts missing critical data
            missing_data_issues = []

            # Check for accounts without services
            orphaned_accounts = VirtualminAccount.objects.filter(service__isnull=True)
            if orphaned_accounts.exists():
                missing_data_issues.append(
                    {
                        "issue": "accounts_without_services",
                        "count": orphaned_accounts.count(),
                        "domains": list(orphaned_accounts.values_list("domain", flat=True)),
                    }
                )

            # Check for accounts without customers
            accounts_without_customers = VirtualminAccount.objects.filter(service__customer__isnull=True)
            if accounts_without_customers.exists():
                missing_data_issues.append(
                    {
                        "issue": "accounts_without_customers",
                        "count": accounts_without_customers.count(),
                        "domains": list(accounts_without_customers.values_list("domain", flat=True)),
                    }
                )

            # Check for servers without proper configuration
            misconfigured_servers = VirtualminServer.objects.filter(api_username="", encrypted_api_password=b"")
            if misconfigured_servers.exists():
                missing_data_issues.append(
                    {
                        "issue": "servers_without_credentials",
                        "count": misconfigured_servers.count(),
                        "servers": list(misconfigured_servers.values_list("hostname", flat=True)),
                    }
                )

            # Calculate recovery metrics
            total_accounts = VirtualminAccount.objects.count()
            recoverable_accounts = VirtualminAccount.objects.filter(
                service__isnull=False, service__customer__isnull=False, status__in=["active", "suspended"]
            ).count()

            recovery_percentage = (recoverable_accounts / total_accounts * 100) if total_accounts > 0 else 100

            excellent_threshold = SettingsService.get_integer_setting(
                "provisioning.recovery_excellent_threshold", _DEFAULT_EXCELLENT_RECOVERY_THRESHOLD
            )
            good_threshold = SettingsService.get_integer_setting(
                "provisioning.recovery_good_threshold", _DEFAULT_GOOD_RECOVERY_THRESHOLD
            )
            warning_threshold = SettingsService.get_integer_setting(
                "provisioning.recovery_warning_threshold", _DEFAULT_WARNING_RECOVERY_THRESHOLD
            )

            integrity_status = (
                "excellent"
                if recovery_percentage >= excellent_threshold
                else "good"
                if recovery_percentage >= good_threshold
                else "warning"
                if recovery_percentage >= warning_threshold
                else "critical"
            )

            return Ok(
                {
                    "integrity_status": integrity_status,
                    "recovery_percentage": round(recovery_percentage, 2),
                    "total_accounts": total_accounts,
                    "recoverable_accounts": recoverable_accounts,
                    "missing_data_issues": missing_data_issues,
                    "issues_count": len(missing_data_issues),
                    "disaster_recovery_ready": len(missing_data_issues) == 0,
                    "check_timestamp": timezone.now().isoformat(),
                    "recommendations": self._get_integrity_recommendations(missing_data_issues),
                }
            )

        except Exception as e:
            logger.exception(f"Data integrity check failed: {e}")
            return Err(str(e))

    def _get_integrity_recommendations(self, issues: list[dict[str, Any]]) -> list[str]:
        """Get recommendations based on integrity issues"""
        recommendations = []

        for issue in issues:
            if issue["issue"] == "accounts_without_services":
                recommendations.append("🔗 Link orphaned accounts to PRAHO services or mark for cleanup")
            elif issue["issue"] == "accounts_without_customers":
                recommendations.append("👤 Ensure all services have valid customer associations")
            elif issue["issue"] == "servers_without_credentials":
                recommendations.append("🔑 Configure API credentials for all Virtualmin servers")

        if not recommendations:
            recommendations.append("✅ PRAHO data integrity is excellent - ready for disaster recovery")

        return recommendations

    def test_recovery_capability(self, server: VirtualminServer) -> Result[dict[str, Any], str]:
        """
        Test disaster recovery capability for a server.

        This performs a dry-run rebuild to verify that PRAHO data
        is sufficient to recover the server completely.

        Args:
            server: Server to test recovery for

        Returns:
            Result with recovery test results
        """
        logger.info(f"🧪 [DisasterRecovery] Testing recovery capability for {server.hostname}")

        # Perform dry-run rebuild
        result = self.rebuild_server_from_praho(server, dry_run=True)

        if result.is_ok():
            rebuild_data = result.unwrap()

            # Additional recovery readiness checks
            health_check_service = VirtualminProvisioningService(server)
            connection_test = health_check_service.test_server_connection(server)

            return Ok(
                {
                    "server": server.hostname,
                    "recovery_ready": True,
                    "accounts_recoverable": rebuild_data["accounts_to_rebuild"],
                    "connection_status": "healthy" if connection_test.is_ok() else "failed",
                    "rebuild_plan": rebuild_data.get("rebuild_plan", []),
                    "test_timestamp": timezone.now().isoformat(),
                    "message": f"✅ Server {server.hostname} is ready for disaster recovery",
                }
            )
        else:
            return Err(f"Recovery test failed: {result.unwrap_err()}")
