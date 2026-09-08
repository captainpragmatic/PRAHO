"""
Virtualmin Disaster Recovery Service - PRAHO Platform
Implements PRAHO-as-Source-of-Truth disaster recovery patterns.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.db import models
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

from .virtualmin_gateway import VirtualminConfig, VirtualminGateway
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_service import VirtualminProvisioningService

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
                    # Capture the pre-loss status BEFORE reprovisioning: the call below
                    # mutates account.status to provisioning/active, so reading it after
                    # would never re-suspend a suspended account and would misreport the
                    # original status in the results.
                    original_status = account.status

                    # 🔒 #326: rebuild must REUSE the existing PRAHO row, not create a new one.
                    # create_virtualmin_account() rejects the domain as "already exists in PRAHO"
                    # (the row being rebuilt is the collision), so it failed for 100% of accounts.
                    # reprovision_virtualmin_account re-runs the server-side create against the
                    # existing row (fresh password, retargeted server).
                    result = provisioning_service.reprovision_virtualmin_account(account, target_server)

                    if result.is_ok():
                        new_account = result.unwrap()

                        # Apply original status
                        if original_status == "suspended":
                            provisioning_service.suspend_account(new_account, "Restored as suspended from PRAHO data")

                        # Apply quotas if they existed (use `is not None` to allow zero = unlimited)
                        if account.disk_quota_mb is not None or account.bandwidth_quota_mb is not None:
                            self._restore_quotas(
                                target_server,
                                account.domain,
                                account.disk_quota_mb,
                                account.bandwidth_quota_mb,
                            )

                        rebuild_results.append(
                            {
                                "domain": account.domain,
                                "status": "success",
                                "new_account_id": str(new_account.id),
                                "original_status": original_status,
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

            # Reconcile server statistics from the authoritative DB state (#326).
            # _execute_domain_creation increments current_domains per success on its own
            # account.server instance, so assigning successful_rebuilds to the loop's
            # target_server here fought those increments and could under/over-count. Recount
            # the active accounts actually on this server instead.
            target_server.current_domains = VirtualminAccount.objects.filter(
                server=target_server, status="active"
            ).count()
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
        """Verify the ACTUAL rebuild input set `reprovision_virtualmin_account` needs.

        Per account: linked service AND customer; a virtualmin_username; both
        recovery-seed ids present AND consistent with the linked rows. Per
        server: a usable credential through the vault-first resolver (the
        legacy encrypted field is deliberately empty for vault-managed rows).
        A missing node_deployment is reported as a transport-capability
        warning, not a rebuild failure — gateway rebuilds work without it.
        """
        try:
            # Check for accounts missing critical data
            missing_data_issues = []
            transport_warnings = []

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

            # Rebuild inputs: username and BOTH recovery-seed ids.
            unnamed = VirtualminAccount.objects.filter(virtualmin_username="")
            if unnamed.exists():
                missing_data_issues.append(
                    {
                        "issue": "accounts_without_virtualmin_username",
                        "count": unnamed.count(),
                        "domains": list(unnamed.values_list("domain", flat=True)),
                    }
                )
            seedless = VirtualminAccount.objects.filter(
                models.Q(praho_service_id__isnull=True) | models.Q(praho_customer_id__isnull=True)
            )
            if seedless.exists():
                missing_data_issues.append(
                    {
                        "issue": "accounts_with_unusable_recovery_seed",
                        "count": seedless.count(),
                        "domains": list(seedless.values_list("domain", flat=True)),
                    }
                )
            # Seed-consistency: the seed ids must match the linked rows. The
            # UUIDField stores Django's int-coercion of the integer pk
            # (UUID(int=pk)), so compare in that form.
            inconsistent = [
                account.domain
                for account in VirtualminAccount.objects.select_related("service").filter(
                    service__isnull=False, praho_service_id__isnull=False
                )
                if account.praho_service_id != uuid.UUID(int=int(account.service_id))
            ]
            if inconsistent:
                missing_data_issues.append(
                    {
                        "issue": "accounts_with_inconsistent_recovery_seed",
                        "count": len(inconsistent),
                        "domains": inconsistent,
                    }
                )

            # Server credentials via the REAL resolution path (vault-first):
            # checking the legacy field alone flags healthy vault-managed rows.
            uncredentialed = [
                server.hostname
                for server in VirtualminServer.objects.all()
                if not self._server_has_usable_credential(server)
            ]
            if uncredentialed:
                missing_data_issues.append(
                    {
                        "issue": "servers_without_usable_credentials",
                        "count": len(uncredentialed),
                        "servers": uncredentialed,
                    }
                )

            # Transport capability (warning class): manually-registered servers
            # can be rebuilt via the gateway but have no archive transport.
            transportless = [
                server.hostname
                for server in VirtualminServer.objects.all()
                if getattr(server, "node_deployment", None) is None
            ]
            if transportless:
                transport_warnings.append(
                    {
                        "issue": "servers_without_node_deployment",
                        "count": len(transportless),
                        "servers": transportless,
                    }
                )

            # Calculate recovery metrics from the FULL input set.
            total_accounts = VirtualminAccount.objects.count()
            recoverable_accounts = (
                VirtualminAccount.objects.filter(
                    service__isnull=False,
                    service__customer__isnull=False,
                    praho_service_id__isnull=False,
                    praho_customer_id__isnull=False,
                    status__in=["active", "suspended"],
                )
                .exclude(virtualmin_username="")
                .count()
            )

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
                    "transport_warnings": transport_warnings,
                    "issues_count": len(missing_data_issues),
                    "disaster_recovery_ready": len(missing_data_issues) == 0,
                    "check_timestamp": timezone.now().isoformat(),
                    "recommendations": self._get_integrity_recommendations(missing_data_issues),
                }
            )

        except Exception as e:
            logger.exception(f"Data integrity check failed: {e}")
            return Err(str(e))

    @staticmethod
    def _server_has_usable_credential(server: VirtualminServer) -> bool:
        """Vault-first, matching the gateway's real resolution order."""
        from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415  # Circular

        try:
            vault_result = get_credential_vault().get_credential(
                service_type="virtualmin",
                service_identifier=server.hostname,
                reason="Disaster-recovery readiness check",
            )
            if vault_result.is_ok():
                username, password, _metadata = vault_result.unwrap()
                if username and password:
                    return True
        except Exception:  # Vault outage must not crash the report
            logger.warning("⚠️ [DR] Vault lookup failed for %s; falling back to the legacy field", server.hostname)
        if not server.api_username:
            return False
        try:
            return bool(server.get_api_password())
        except Exception:  # Undecryptable legacy field == unusable
            return False

    def _restore_quotas(
        self,
        server: VirtualminServer,
        domain: str,
        disk_quota_mb: int | None,
        bandwidth_quota_mb: int | None,
    ) -> None:
        """Restore disk and bandwidth quotas for a rebuilt domain via Virtualmin API."""
        params: dict[str, str] = {"domain": domain}
        if disk_quota_mb is not None:
            params["quota"] = str(disk_quota_mb)
        if bandwidth_quota_mb is not None:
            params["bw"] = str(bandwidth_quota_mb)

        try:
            config = VirtualminConfig(server=server)
            gateway = VirtualminGateway(config)
            result = gateway.call("modify-domain", params)
            if result.is_ok():
                logger.info(
                    f"✅ [DisasterRecovery] Restored quotas for {domain}: "
                    f"disk={disk_quota_mb}MB, bandwidth={bandwidth_quota_mb}MB"
                )
            else:
                logger.warning(f"⚠️ [DisasterRecovery] Failed to restore quotas for {domain}: {result.unwrap_err()}")
        except Exception as e:
            logger.warning(f"⚠️ [DisasterRecovery] Quota restoration error for {domain}: {e}")

    def _get_integrity_recommendations(self, issues: list[dict[str, Any]]) -> list[str]:
        """Get recommendations based on integrity issues"""
        recommendations = []

        advice = {
            "accounts_without_services": "🔗 Link orphaned accounts to PRAHO services or mark for cleanup",
            "accounts_without_customers": "👤 Ensure all services have valid customer associations",
            "accounts_without_virtualmin_username": "🏷️ Backfill the Virtualmin username on every account",
            "accounts_with_unusable_recovery_seed": "🌱 Populate both PRAHO service and customer ids (recovery seed)",
            "accounts_with_inconsistent_recovery_seed": "🌱 Reconcile recovery-seed ids with the linked service/customer",
            "servers_without_usable_credentials": "🔑 Store a usable API credential (vault or field) for every server",
        }
        for issue in issues:
            tip = advice.get(issue["issue"])
            if tip:
                recommendations.append(tip)

        # Only claim readiness when there are genuinely no blocking issues —
        # never alongside a critical report (the dishonest-publication class
        # this branch exists to eliminate).
        if not issues:
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
            connection_healthy = connection_test.is_ok()

            # 🔒 FAIL-CLOSED (#326): a dry-run only counts PRAHO rows — it does NOT prove the
            # rebuild create-path works. Readiness previously hardcoded True and claimed
            # "✅ ready" even when this connection test FAILED, so operators trusted a
            # capability that was 0%-functional. Readiness now requires, at minimum, a
            # reachable server; and because the create-path itself is not yet exercised
            # here, the message is explicit that this is a data-presence check, not a
            # proven end-to-end recovery.
            recovery_ready = connection_healthy
            if not connection_healthy:
                message = (
                    f"❌ Server {server.hostname} is NOT recovery-ready: "
                    f"connection test failed ({connection_test.unwrap_err()})"
                )
            else:
                message = (
                    f"Server {server.hostname} reachable and {rebuild_data['accounts_to_rebuild']} "
                    "account(s) present in PRAHO (data-presence check only — the rebuild create-path "
                    "is not exercised by this dry run)"
                )

            return Ok(
                {
                    "server": server.hostname,
                    "recovery_ready": recovery_ready,
                    "accounts_recoverable": rebuild_data["accounts_to_rebuild"],
                    "connection_status": "healthy" if connection_healthy else "failed",
                    "rebuild_plan": rebuild_data.get("rebuild_plan", []),
                    "test_timestamp": timezone.now().isoformat(),
                    "message": message,
                }
            )
        else:
            return Err(f"Recovery test failed: {result.unwrap_err()}")
