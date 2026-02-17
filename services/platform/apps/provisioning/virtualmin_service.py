"""
Virtualmin Business Logic Service - PRAHO Platform
High-level service operations for Virtualmin provisioning and management.

Implements:
- Idempotency: Provisioning operations can be safely retried
- Rollback Mechanisms: Failed provisioning attempts are cleaned up
"""

from __future__ import annotations

import logging
import secrets
import string
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .security_utils import IdempotencyManager
from .virtualmin_backup_service import BackupConfig, RestoreConfig
from .virtualmin_gateway import VirtualminConfig, VirtualminGateway, get_virtualmin_config
from .virtualmin_models import (
    VirtualminAccount,
    VirtualminDriftRecord,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_validators import VirtualminValidator

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Username generation constants
MIN_USERNAME_LENGTH = 3
_DEFAULT_MAX_USERNAME_UNIQUENESS_ATTEMPTS = 1000
MAX_USERNAME_UNIQUENESS_ATTEMPTS = _DEFAULT_MAX_USERNAME_UNIQUENESS_ATTEMPTS


def get_max_username_uniqueness_attempts() -> int:
    """Get max username uniqueness attempts from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting(
        "provisioning.max_username_uniqueness_attempts", _DEFAULT_MAX_USERNAME_UNIQUENESS_ATTEMPTS
    )


@dataclass
class VirtualminAccountCreationData:
    """Data class to encapsulate Virtualmin account creation parameters"""

    service: Any  # Service
    domain: str
    username: str | None = None
    password: str | None = None
    template: str = "Default"
    server: Any | None = None  # VirtualminServer


class VirtualminProvisioningService:
    """
    High-level Virtualmin provisioning service.

    Handles business logic for account creation, management, and lifecycle.
    Integrates with PRAHO's service management and customer billing.
    """

    def __init__(self, server: VirtualminServer | None = None):
        self.server = server
        self._gateway: VirtualminGateway | None = None

    def _get_gateway(self, server: VirtualminServer | None = None) -> VirtualminGateway:
        """Get or create gateway for server"""
        target_server = server or self.server

        if not target_server:
            raise ValidationError("No server specified for gateway")

        if not self._gateway or (server and server != self.server):
            # Get configuration from SystemSettings + environment
            config_data = get_virtualmin_config()

            # Create VirtualminConfig with server and override SSL settings
            config = VirtualminConfig(
                server=target_server,
                timeout=config_data["timeout"],
                verify_ssl=config_data.get("ssl_verify", target_server.ssl_verify),
                cert_fingerprint=target_server.ssl_cert_fingerprint or config_data.get("pinned_cert_sha256", ""),
            )

            self._gateway = VirtualminGateway(config)

        return self._gateway

    def create_virtualmin_account(self, creation_data: VirtualminAccountCreationData) -> Result[VirtualminAccount, str]:
        """
        Create new Virtualmin account for PRAHO service.

        Args:
            creation_data: VirtualminAccountCreationData object containing all creation parameters

        Returns:
            Result with created VirtualminAccount or error message
        """
        try:
            # Input validation
            domain = VirtualminValidator.validate_domain_name(creation_data.domain)
            template = VirtualminValidator.validate_template_name(creation_data.template)

            # Auto-generate username if not provided
            if not creation_data.username:
                username = self._generate_username_from_domain(domain)
            else:
                username = VirtualminValidator.validate_username(creation_data.username)

            # Auto-generate password if not provided
            if not creation_data.password:
                password = self._generate_secure_password()
            else:
                password = VirtualminValidator.validate_password(creation_data.password)

            # Select server if not provided
            if not creation_data.server:
                server_result = self._select_best_server()
                if server_result.is_err():
                    return Err(f"Server selection failed: {server_result.unwrap_err()}")
                server = server_result.unwrap()
            else:
                server = creation_data.server

            # Check if domain already exists
            existing_account = VirtualminAccount.objects.filter(domain=domain).first()
            if existing_account:
                return Err(f"Domain {domain} already exists in PRAHO")

            # Create account record
            with transaction.atomic():
                account = VirtualminAccount(
                    domain=domain,
                    service=creation_data.service,
                    server=server,
                    virtualmin_username=username,
                    template_name=template,
                    status="provisioning",
                    praho_customer_id=creation_data.service.customer.id,
                    praho_service_id=creation_data.service.id,
                )
                account.set_password(password)
                account.save()

                # Create provisioning job
                job = VirtualminProvisioningJob(
                    operation="create_domain",
                    server=server,
                    account=account,
                    parameters={
                        "domain": domain,
                        "username": username,
                        "template": template,
                        "recovery_seed": account.get_recovery_seed(),
                    },
                    correlation_id=f"create_domain_{account.id}",
                )
                job.save()

            # Execute provisioning
            provisioning_result = self._execute_domain_creation(account, job)

            if provisioning_result.is_ok():
                logger.info(
                    f"✅ [VirtualminService] Created account {domain} for customer {creation_data.service.customer.id}"
                )
                return Ok(account)
            else:
                error_msg = provisioning_result.unwrap_err()
                logger.error(f"❌ [VirtualminService] Failed to create account {domain}: {error_msg}")

                # Update account status
                account.status = "error"
                account.status_message = error_msg
                account.save(update_fields=["status", "status_message", "updated_at"])

                return Err(error_msg)

        except ValidationError as e:
            return Err(f"Validation error: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error creating Virtualmin account: {e}")
            return Err(f"Internal error: {e}")

    def _execute_domain_creation(
        self, account: VirtualminAccount, job: VirtualminProvisioningJob
    ) -> Result[dict[str, Any], str]:
        """Execute domain creation on Virtualmin server with validation and rollback"""
        try:
            gateway = self._get_gateway(account.server)

            # Mark job as started
            job.mark_started()

            # ===============================================================================
            # PHASE 1: PRE-FLIGHT VALIDATION 🚀 (Quick Win)
            # ===============================================================================
            logger.info(f"🔍 [VirtualminService] Pre-flight validation for {account.domain}")

            validation_result = self._validate_provisioning_preconditions(account, gateway)
            if validation_result.is_err():
                error_msg = validation_result.unwrap_err()
                job.mark_failed(f"Validation failed: {error_msg}")
                return Err(f"Pre-flight validation failed: {error_msg}")

            logger.info(f"✅ [VirtualminService] Pre-flight validation passed for {account.domain}")

            # ===============================================================================
            # PHASE 2: ROLLBACK TRACKING SETUP 🔄
            # ===============================================================================
            rollback_operations: list[dict[str, Any]] = []

            # Prepare domain creation parameters
            params = {
                "domain": account.domain,
                "user": account.virtualmin_username,
                "pass": account.get_password(),
                "template": account.template_name,
                "comment": account.get_recovery_seed(),  # Store recovery seed
            }

            # Add quota limits if specified
            if account.disk_quota_mb:
                params["quota"] = str(account.disk_quota_mb)

            if account.bandwidth_quota_mb:
                params["bw-limit"] = str(account.bandwidth_quota_mb)

            # Make API call
            result = gateway.call("create-domain", params, correlation_id=job.correlation_id)

            if result.is_ok():
                response = result.unwrap()

                if response.success:
                    # Track successful domain creation for potential rollback
                    rollback_operations.append(
                        {
                            "operation": "delete-domain",
                            "params": {"domain": account.domain},
                            "description": f"Delete domain {account.domain}",
                        }
                    )

                    try:
                        # Update account status
                        account.status = "active"
                        account.provisioned_at = timezone.now()
                        account.save(update_fields=["status", "provisioned_at", "updated_at"])

                        # Update server stats (track for rollback)
                        old_domain_count = account.server.current_domains
                        account.server.current_domains += 1
                        account.server.save(update_fields=["current_domains", "updated_at"])

                        rollback_operations.append(
                            {
                                "operation": "revert_server_stats",
                                "params": {"domain_count": old_domain_count},
                                "description": f"Revert server domain count to {old_domain_count}",
                            }
                        )

                        # Mark job as completed
                        job.mark_completed(response.data, rollback_operations)

                        logger.info(f"✅ [VirtualminService] Successfully created domain {account.domain}")
                        return Ok(response.data)

                    except Exception as db_error:
                        # Database update failed - rollback Virtualmin domain creation
                        logger.error(f"🔥 [VirtualminService] Database update failed for {account.domain}: {db_error}")
                        rollback_status, rollback_details = self._execute_rollback(
                            rollback_operations, gateway, account
                        )
                        if rollback_status == "failed":
                            logger.error(f"🚨 [VirtualminService] CRITICAL: Rollback failed for {account.domain}")

                        job.mark_failed(
                            f"Database update failed: {db_error}",
                            rollback_executed=True,
                            rollback_status=rollback_status,
                            rollback_details=rollback_details,
                        )
                        return Err(f"Provisioning failed during database update: {db_error}")

                else:
                    error_msg = response.data.get("error", "Domain creation failed")
                    job.mark_failed(error_msg, response.data)
                    return Err(error_msg)

            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg)
                return Err(error_msg)

        except Exception as e:
            logger.exception(f"Error executing domain creation: {e}")
            job.mark_failed(str(e))
            return Err(str(e))

    def _check_server_capacity(self, account: VirtualminAccount, health_result: Result[Any, str]) -> Result[None, str]:
        """Check server capacity and disk space"""
        # Check server capacity
        if account.server.max_domains and account.server.current_domains >= account.server.max_domains:
            return Err(
                f"Server {account.server.name} at capacity ({account.server.current_domains}/{account.server.max_domains} domains)"
            )

        # Check disk space if quota specified
        if account.disk_quota_mb and health_result.is_ok():
            server_info = health_result.unwrap()
            available_mb = server_info.get("available_disk_mb", 0)
            if available_mb < account.disk_quota_mb:
                return Err(f"Insufficient disk space: {available_mb}MB available, {account.disk_quota_mb}MB requested")

        return Ok(None)

    def _check_domain_conflicts(self, account: VirtualminAccount, gateway: VirtualminGateway) -> Result[None, str]:
        """Check for domain and username conflicts"""
        # Verify domain doesn't already exist on server
        domain_check = gateway.call("list-domains", {"domain": account.domain})
        if domain_check.is_ok() and domain_check.unwrap().success:
            domains = domain_check.unwrap().data.get("domains", [])
            if any(d.get("domain") == account.domain for d in domains):
                return Err(f"Domain {account.domain} already exists on server")

        # Check if username conflicts exist
        user_check = gateway.call("list-users", {"user": account.virtualmin_username})
        if user_check.is_ok() and user_check.unwrap().success:
            users = user_check.unwrap().data.get("users", [])
            if any(u.get("user") == account.virtualmin_username for u in users):
                return Err(f"Username {account.virtualmin_username} already exists on server")

        return Ok(None)

    def _check_template_availability(self, account: VirtualminAccount, gateway: VirtualminGateway) -> Result[None, str]:
        """Check if required template exists"""
        template_check = gateway.call("list-templates")
        if template_check.is_ok() and template_check.unwrap().success:
            templates = template_check.unwrap().data.get("templates", [])
            if not any(t.get("name") == account.template_name for t in templates):
                return Err(f"Template {account.template_name} not found on server")

        return Ok(None)

    def _validate_provisioning_preconditions(
        self, account: VirtualminAccount, gateway: VirtualminGateway
    ) -> Result[bool, str]:
        """
        Validate all preconditions before provisioning (Phase 1 - Quick Win).

        Checks:
        - Server capacity and health
        - Domain availability
        - Resource limits
        - Template existence
        - User conflicts
        """
        try:
            # 1. Server health check
            health_result = self.health_check_server(account.server)  # type: ignore[attr-defined]
            if health_result.is_err():
                return Err(f"Server health check failed: {health_result.unwrap_err()}")

            # 2. Check server capacity and disk space
            capacity_result = self._check_server_capacity(account, health_result)
            if capacity_result.is_err():
                return Err(capacity_result.unwrap_err())

            # 3. Check domain and username conflicts
            conflict_result = self._check_domain_conflicts(account, gateway)
            if conflict_result.is_err():
                return Err(conflict_result.unwrap_err())

            # 4. Check template availability
            template_result = self._check_template_availability(account, gateway)
            if template_result.is_err():
                return Err(template_result.unwrap_err())

            logger.info(f"✅ [VirtualminService] All preconditions validated for {account.domain}")
            return Ok(True)

        except Exception as e:
            logger.exception(f"🔥 [VirtualminService] Validation error for {account.domain}: {e}")
            return Err(f"Validation error: {e}")

    def _execute_rollback(  # noqa: C901, PLR0912, PLR0915
        self, rollback_operations: list[dict[str, Any]], gateway: VirtualminGateway, account: VirtualminAccount
    ) -> tuple[str, dict[str, Any]]:
        """
        Execute rollback operations in reverse order (Phase 2).

        Args:
            rollback_operations: List of operations to rollback
            gateway: Virtualmin gateway for API calls
            account: Account being rolled back

        Returns:
            Tuple of (rollback_status, rollback_details) where:
            - rollback_status: "success", "partial", or "failed"
            - rollback_details: Dict with operation results
        """
        rollback_details: dict[str, Any] = {
            "operations": [],
            "total_operations": len(rollback_operations),
            "successful_operations": 0,
            "failed_operations": 0,
        }

        try:
            logger.warning(f"⚠️ [VirtualminService] Starting rollback for {account.domain}")

            # Execute rollback operations in reverse order
            for operation in reversed(rollback_operations):
                op_result = {"operation": operation["operation"], "description": operation.get("description", "")}
                try:
                    if operation["operation"] == "delete-domain":
                        result = gateway.call("delete-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            logger.error(f"🔥 [VirtualminService] Failed to rollback domain deletion: {operation}")
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "revert_server_stats":
                        account.server.current_domains = operation["params"]["domain_count"]
                        account.server.save(update_fields=["current_domains", "updated_at"])
                        op_result["status"] = "success"
                        rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "enable-domain":
                        # Rollback for suspend operation - re-enable the domain
                        result = gateway.call("enable-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "disable-domain":
                        # Rollback for unsuspend operation - re-disable the domain
                        result = gateway.call("disable-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    else:
                        op_result["status"] = "skipped"
                        op_result["reason"] = f"Unknown operation type: {operation['operation']}"

                    logger.info(
                        f"✅ [VirtualminService] Rolled back: {operation.get('description', operation['operation'])}"
                    )

                except Exception as op_error:
                    logger.error(
                        f"🔥 [VirtualminService] Rollback operation failed: {operation.get('description', '')} - {op_error}"
                    )
                    op_result["status"] = "failed"
                    op_result["error"] = str(op_error)
                    rollback_details["failed_operations"] += 1
                    # Continue with other rollback operations even if one fails

                rollback_details["operations"].append(op_result)

            # Update account status to failed
            account.status = "error"
            account.status_message = "Provisioning failed - rollback executed"
            account.save(update_fields=["status", "status_message", "updated_at"])

            # Determine overall rollback status
            if rollback_details["failed_operations"] == 0:
                rollback_status = "success"
                logger.warning(f"⚠️ [VirtualminService] Rollback completed successfully for {account.domain}")
            elif rollback_details["successful_operations"] > 0:
                rollback_status = "partial"
                logger.warning(f"⚠️ [VirtualminService] Rollback partially completed for {account.domain}")
            else:
                rollback_status = "failed"
                logger.error(f"🚨 [VirtualminService] Rollback failed for {account.domain}")

            return rollback_status, rollback_details

        except Exception as e:
            logger.exception(f"🚨 [VirtualminService] CRITICAL: Rollback execution failed for {account.domain}: {e}")
            rollback_details["error"] = str(e)
            return "failed", rollback_details

    def suspend_account(self, account: VirtualminAccount, reason: str = "") -> Result[bool, str]:  # noqa: PLR0911
        """
        Suspend Virtualmin account with idempotency and rollback support.

        Args:
            account: VirtualminAccount to suspend
            reason: Reason for suspension

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already suspended.

        Rollback:
            If database update fails after API call succeeds, will attempt
            to re-enable the domain in Virtualmin.
        """
        try:
            # Idempotency check - already suspended
            if account.status == "suspended":
                logger.info(f"⏭️ [VirtualminService] Account {account.domain} already suspended (idempotent)")
                return Ok(True)

            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "suspend_account", {"domain": account.domain, "reason": reason}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                if isinstance(existing_result, dict) and existing_result.get("success"):
                    logger.info(f"✅ [VirtualminService] Returning cached suspend result for {account.domain}")
                    return Ok(True)
                else:
                    logger.warning(f"⚠️ [VirtualminService] Suspend operation already in progress for {account.domain}")
                    return Err("Operation already in progress")

            gateway = self._get_gateway(account.server)

            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="suspend_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain, "reason": reason},
                correlation_id=f"suspend_domain_{account.id}",
            )
            job.save()
            job.mark_started()

            try:
                # Make API call
                result = gateway.call("disable-domain", {"domain": account.domain}, correlation_id=job.correlation_id)

                if result.is_ok():
                    response = result.unwrap()

                    if response.success:
                        # Prepare rollback operation in case DB update fails
                        rollback_operations = [
                            {
                                "operation": "enable-domain",
                                "params": {"domain": account.domain},
                                "description": f"Re-enable domain {account.domain} if DB update fails",
                            }
                        ]

                        try:
                            account.status = "suspended"
                            account.status_message = reason
                            account.save(update_fields=["status", "status_message", "updated_at"])

                            job.mark_completed(response.data)

                            # Mark idempotency as complete
                            IdempotencyManager.complete(idempotency_key, {"success": True})

                            logger.info(f"✅ [VirtualminService] Suspended account {account.domain}")
                            return Ok(True)

                        except Exception as db_error:
                            # Database update failed - rollback the API operation
                            logger.error(
                                f"🔥 [VirtualminService] DB update failed for suspend {account.domain}: {db_error}"
                            )
                            rollback_status, rollback_details = self._execute_rollback(
                                rollback_operations, gateway, account
                            )

                            job.mark_failed(
                                f"Database update failed: {db_error}",
                                rollback_executed=True,
                                rollback_status=rollback_status,
                                rollback_details=rollback_details,
                            )
                            IdempotencyManager.clear(idempotency_key)
                            return Err(f"Suspension failed during database update: {db_error}")
                    else:
                        error_msg = response.data.get("error", "Suspension failed")
                        job.mark_failed(error_msg, response.data)
                        IdempotencyManager.clear(idempotency_key)
                        return Err(error_msg)

                else:
                    error = result.unwrap_err()
                    error_msg = str(error)
                    job.mark_failed(error_msg)
                    IdempotencyManager.clear(idempotency_key)
                    return Err(error_msg)

            except Exception:
                IdempotencyManager.clear(idempotency_key)
                raise

        except Exception as e:
            logger.exception(f"Error suspending account {account.domain}: {e}")
            return Err(str(e))

    def unsuspend_account(self, account: VirtualminAccount) -> Result[bool, str]:  # noqa: PLR0911
        """
        Unsuspend (reactivate) Virtualmin account with idempotency and rollback support.

        Args:
            account: VirtualminAccount to unsuspend

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already active.

        Rollback:
            If database update fails after API call succeeds, will attempt
            to re-disable the domain in Virtualmin.
        """
        try:
            # Idempotency check - already active
            if account.status == "active":
                logger.info(f"⏭️ [VirtualminService] Account {account.domain} already active (idempotent)")
                return Ok(True)

            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "unsuspend_account", {"domain": account.domain}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                if isinstance(existing_result, dict) and existing_result.get("success"):
                    logger.info(f"✅ [VirtualminService] Returning cached unsuspend result for {account.domain}")
                    return Ok(True)
                else:
                    logger.warning(
                        f"⚠️ [VirtualminService] Unsuspend operation already in progress for {account.domain}"
                    )
                    return Err("Operation already in progress")

            gateway = self._get_gateway(account.server)

            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="unsuspend_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain},
                correlation_id=f"unsuspend_domain_{account.id}",
            )
            job.save()
            job.mark_started()

            try:
                # Make API call
                result = gateway.call("enable-domain", {"domain": account.domain}, correlation_id=job.correlation_id)

                if result.is_ok():
                    response = result.unwrap()

                    if response.success:
                        # Prepare rollback operation in case DB update fails
                        rollback_operations = [
                            {
                                "operation": "disable-domain",
                                "params": {"domain": account.domain},
                                "description": f"Re-disable domain {account.domain} if DB update fails",
                            }
                        ]

                        try:
                            account.status = "active"
                            account.status_message = ""
                            account.save(update_fields=["status", "status_message", "updated_at"])

                            job.mark_completed(response.data)

                            # Mark idempotency as complete
                            IdempotencyManager.complete(idempotency_key, {"success": True})

                            logger.info(f"✅ [VirtualminService] Unsuspended account {account.domain}")
                            return Ok(True)

                        except Exception as db_error:
                            # Database update failed - rollback the API operation
                            logger.error(
                                f"🔥 [VirtualminService] DB update failed for unsuspend {account.domain}: {db_error}"
                            )
                            rollback_status, rollback_details = self._execute_rollback(
                                rollback_operations, gateway, account
                            )

                            job.mark_failed(
                                f"Database update failed: {db_error}",
                                rollback_executed=True,
                                rollback_status=rollback_status,
                                rollback_details=rollback_details,
                            )
                            IdempotencyManager.clear(idempotency_key)
                            return Err(f"Unsuspension failed during database update: {db_error}")
                    else:
                        error_msg = response.data.get("error", "Unsuspension failed")
                        job.mark_failed(error_msg, response.data)
                        IdempotencyManager.clear(idempotency_key)
                        return Err(error_msg)

                else:
                    error = result.unwrap_err()
                    error_msg = str(error)
                    job.mark_failed(error_msg)
                    IdempotencyManager.clear(idempotency_key)
                    return Err(error_msg)

            except Exception:
                IdempotencyManager.clear(idempotency_key)
                raise

        except Exception as e:
            logger.exception(f"Error unsuspending account {account.domain}: {e}")
            return Err(str(e))

    def delete_account(self, account: VirtualminAccount) -> Result[bool, str]:  # noqa: PLR0911, PLR0912, PLR0915
        """
        Delete Virtualmin account permanently with idempotency and rollback support.

        Args:
            account: VirtualminAccount to delete

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already terminated.

        Rollback:
            If database update fails after API call succeeds, logs the inconsistency
            (domain deleted in Virtualmin but not marked as such in DB).
            Note: Domain deletion cannot be rolled back - data loss is irreversible.
        """
        # ⚠️ SAFETY CHECK: Prevent deletion of protected accounts
        if account.protected_from_deletion:
            error_msg = f"Account {account.domain} is protected from deletion. Disable protection first."
            logger.warning(f"🛡️ [VirtualminService] {error_msg}")
            return Err(error_msg)

        # Idempotency check - already terminated
        if account.status == "terminated":
            logger.info(f"⏭️ [VirtualminService] Account {account.domain} already terminated (idempotent)")
            return Ok(True)

        # Additional safety check - only allow deletion of terminated/error accounts
        # Note: We check for 'error' status separately since terminated is handled above
        if account.status not in ["error"]:
            error_msg = f"Account {account.domain} must be terminated or in error state before deletion (current: {account.status})"
            logger.warning(f"🛡️ [VirtualminService] {error_msg}")
            return Err(error_msg)

        try:
            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "delete_account", {"domain": account.domain}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                if isinstance(existing_result, dict) and existing_result.get("success"):
                    logger.info(f"✅ [VirtualminService] Returning cached delete result for {account.domain}")
                    return Ok(True)
                else:
                    logger.warning(f"⚠️ [VirtualminService] Delete operation already in progress for {account.domain}")
                    return Err("Operation already in progress")

            gateway = self._get_gateway(account.server)

            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="delete_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain},
                correlation_id=f"delete_domain_{account.id}",
            )
            job.save()
            job.mark_started()

            # Store original server domain count for potential rollback
            original_domain_count = account.server.current_domains

            try:
                # Make API call
                result = gateway.call("delete-domain", {"domain": account.domain}, correlation_id=job.correlation_id)

                if result.is_ok():
                    response = result.unwrap()

                    if response.success:
                        try:
                            # Update server stats
                            account.server.current_domains = max(0, account.server.current_domains - 1)
                            account.server.save(update_fields=["current_domains", "updated_at"])

                            # Mark account as terminated (don't delete for audit trail)
                            account.status = "terminated"
                            account.save(update_fields=["status", "updated_at"])

                            job.mark_completed(response.data)

                            # Mark idempotency as complete
                            IdempotencyManager.complete(idempotency_key, {"success": True})

                            logger.info(f"✅ [VirtualminService] Deleted account {account.domain}")
                            return Ok(True)

                        except Exception as db_error:
                            # Database update failed - domain is already deleted in Virtualmin
                            # This is a critical inconsistency - log it but can't rollback deletion
                            logger.error(
                                f"🚨 [VirtualminService] CRITICAL: DB update failed after domain deletion for {account.domain}: {db_error}"
                            )

                            # Track the rollback attempt (even though we can't restore the domain)
                            rollback_details = {
                                "operations": [
                                    {
                                        "operation": "restore-domain",
                                        "status": "not_possible",
                                        "description": "Domain deletion cannot be rolled back - data is irreversibly lost",
                                    }
                                ],
                                "total_operations": 1,
                                "successful_operations": 0,
                                "failed_operations": 1,
                                "critical_note": f"Domain {account.domain} deleted in Virtualmin but DB not updated",
                            }

                            job.mark_failed(
                                f"Database update failed after domain deletion: {db_error}",
                                rollback_executed=True,
                                rollback_status="failed",
                                rollback_details=rollback_details,
                            )
                            IdempotencyManager.clear(idempotency_key)

                            # Try to at least revert server stats
                            try:
                                account.server.current_domains = original_domain_count
                                account.server.save(update_fields=["current_domains", "updated_at"])
                                logger.info(f"✅ [VirtualminService] Reverted server domain count for {account.domain}")
                            except Exception as revert_error:
                                logger.error(f"🔥 [VirtualminService] Failed to revert server stats: {revert_error}")

                            return Err(
                                f"Deletion failed during database update (CRITICAL: domain already deleted): {db_error}"
                            )

                    else:
                        error_msg = response.data.get("error", "Deletion failed")
                        job.mark_failed(error_msg, response.data)
                        IdempotencyManager.clear(idempotency_key)
                        return Err(error_msg)

                else:
                    error = result.unwrap_err()
                    error_msg = str(error)
                    job.mark_failed(error_msg)
                    IdempotencyManager.clear(idempotency_key)
                    return Err(error_msg)

            except Exception:
                IdempotencyManager.clear(idempotency_key)
                raise

        except Exception as e:
            logger.exception(f"Error deleting account {account.domain}: {e}")
            return Err(str(e))

    def _select_best_server(self) -> Result[VirtualminServer, str]:
        """
        Select best available server for new domain.

        Uses capacity-based placement with health checks.

        Returns:
            Result with selected server or error message
        """
        # Get healthy, active servers that can host domains
        available_servers = (
            VirtualminServer.objects.filter(status="active")
            .exclude(current_domains__gte=models.F("max_domains"))
            .order_by("current_domains")
        )  # Prefer servers with lower load

        for server in available_servers:
            if server.can_host_domain():
                return Ok(server)

        return Err("No available servers can host new domains")

    def _generate_username_from_domain(self, domain: str) -> str:
        """
        Generate Virtualmin username from domain name.

        Args:
            domain: Domain name

        Returns:
            Valid Virtualmin username
        """
        # Remove TLD and special characters
        base = domain.split(".", maxsplit=1)[0]
        username = "".join(c for c in base if c.isalnum())

        # Ensure minimum length and uniqueness
        if len(username) < MIN_USERNAME_LENGTH:
            username = f"user{username}"

        # Truncate to maximum length
        username = username[:32]

        # Ensure uniqueness by checking existing accounts
        original_username = username
        counter = 1

        while VirtualminAccount.objects.filter(virtualmin_username=username).exists():
            username = f"{original_username}{counter}"[:32]
            counter += 1

            # Prevent infinite loop
            if counter > MAX_USERNAME_UNIQUENESS_ATTEMPTS:
                username = f"user_{uuid.uuid4().hex[:8]}"
                break

        return username

    def _generate_secure_password(self, length: int = 16) -> str:
        """
        Generate secure password for Virtualmin account.

        Args:
            length: Password length

        Returns:
            Secure password string
        """
        # Character sets for password generation
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-="

        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend([secrets.choice(all_chars) for _ in range(length - 4)])

        # Shuffle the password list
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def test_server_connection(self, server: VirtualminServer) -> Result[dict[str, Any], str]:
        """
        Test connection to Virtualmin server.

        Args:
            server: Server to test

        Returns:
            Result with connection info or error message
        """
        try:
            gateway = self._get_gateway(server)
            return gateway.test_connection()
        except Exception as e:
            return Err(f"Connection test failed: {e}")

    def sync_account_from_virtualmin(self, account: VirtualminAccount) -> Result[dict[str, Any], str]:
        """
        Sync account state from Virtualmin server.

        This should be used sparingly - PRAHO is the source of truth.
        Only use for drift detection and emergency recovery.
        """
        try:
            gateway = self._get_gateway(account.server)

            # Get current state from Virtualmin
            result = gateway.call("list-domains", {"domain": account.domain})
            if result.is_err():
                return Err(f"Failed to query Virtualmin: {result.unwrap_err()}")

            response = result.unwrap()
            virtualmin_data = response.data

            # Detect drift between PRAHO and Virtualmin
            drift_detected = []

            # Check domain existence
            if not virtualmin_data.get("domains"):
                drift_detected.append("Domain missing from Virtualmin")

            # Check account status
            virtualmin_status = virtualmin_data.get("status", "unknown")
            expected_status = "active" if account.status == "active" else "disabled"
            if virtualmin_status != expected_status:
                drift_detected.append(f"Status mismatch: PRAHO={account.status}, Virtualmin={virtualmin_status}")

            if drift_detected:
                # Log drift for audit
                VirtualminDriftRecord.objects.create(  # type: ignore[misc]
                    account=account,
                    drift_type="status_mismatch",
                    praho_state={"status": account.status, "domain": account.domain},
                    virtualmin_state=virtualmin_data,
                    drift_description="; ".join(drift_detected),
                    resolution_action="logged_for_review",
                )

                logger.warning(f"🔍 [VirtualminService] Drift detected for {account.domain}: {drift_detected}")

            return Ok(
                {
                    "drift_detected": drift_detected,
                    "virtualmin_state": virtualmin_data,
                    "praho_state": {"status": account.status, "domain": account.domain},
                }
            )

        except Exception as e:
            logger.exception(f"Error syncing account {account.domain}: {e}")
            return Err(str(e))

    def enforce_praho_state(self, account: VirtualminAccount, force: bool = False) -> Result[dict[str, Any], str]:
        """
        🚨 CRITICAL: Enforce PRAHO state as source of truth.

        When drift is detected, this method forces Virtualmin to match PRAHO's state.
        Use with caution - this can overwrite manual changes in Virtualmin.

        Args:
            account: VirtualminAccount to enforce
            force: If True, apply changes without confirmation

        Returns:
            Result with enforcement actions taken
        """
        try:
            # First detect drift
            sync_result = self.sync_account_from_virtualmin(account)
            if sync_result.is_err():
                return sync_result

            sync_data = sync_result.unwrap()
            drift_detected = sync_data["drift_detected"]

            if not drift_detected:
                return Ok({"message": "No drift detected, PRAHO state matches Virtualmin"})

            if not force:
                return Ok(
                    {
                        "drift_detected": drift_detected,
                        "message": "Drift detected but force=False. Use force=True to apply corrections.",
                        "praho_state": sync_data["praho_state"],
                        "virtualmin_state": sync_data["virtualmin_state"],
                    }
                )

            # Enforce PRAHO state
            actions_taken = []
            gateway = self._get_gateway(account.server)

            # Enforce account status
            if account.status == "active":
                result = gateway.call("enable-domain", {"domain": account.domain})
                if result.is_ok():
                    actions_taken.append("enabled_domain")
            elif account.status == "suspended":
                result = gateway.call("disable-domain", {"domain": account.domain})
                if result.is_ok():
                    actions_taken.append("suspended_domain")

            # Log enforcement action
            VirtualminDriftRecord.objects.create(  # type: ignore[misc]
                account=account,
                drift_type="praho_state_enforced",
                praho_state=sync_data["praho_state"],
                virtualmin_state=sync_data["virtualmin_state"],
                drift_description=f"Enforced PRAHO state: {actions_taken}",
                resolution_action="praho_state_enforced",
            )

            logger.warning(f"🚨 [VirtualminService] Enforced PRAHO state for {account.domain}: {actions_taken}")

            return Ok(
                {
                    "actions_taken": actions_taken,
                    "drift_resolved": drift_detected,
                    "enforcement_timestamp": timezone.now().isoformat(),
                }
            )

        except Exception as e:
            logger.exception(f"Error enforcing PRAHO state for {account.domain}: {e}")
            return Err(str(e))


class VirtualminServerManagementService:
    """Service for managing Virtualmin servers and health monitoring"""

    def health_check_server(self, server: VirtualminServer) -> Result[dict[str, Any], str]:
        """
        Perform health check on Virtualmin server.

        Args:
            server: Server to check

        Returns:
            Result with health data or error message
        """
        try:
            provisioning_service = VirtualminProvisioningService(server)
            result = provisioning_service.test_server_connection(server)

            if result.is_ok():
                health_data = result.unwrap()

                # Update server health status
                server.last_health_check = timezone.now()
                server.health_check_error = ""
                server.save(update_fields=["last_health_check", "health_check_error", "updated_at"])

                logger.info(f"✅ [ServerManagement] Health check passed for {server.hostname}")
                return Ok(health_data)
            else:
                error_msg = result.unwrap_err()

                # Update server with error and mark as failed
                server.last_health_check = timezone.now()
                server.health_check_error = error_msg
                server.status = "failed"
                server.save(update_fields=["last_health_check", "health_check_error", "status", "updated_at"])

                logger.warning(f"⚠️ [ServerManagement] Health check failed for {server.hostname}: {error_msg}")
                return Err(error_msg)

        except Exception as e:
            logger.exception(f"Error in health check for {server.hostname}: {e}")
            return Err(str(e))

    def update_server_statistics(self, server: VirtualminServer) -> Result[dict[str, Any], str]:
        """
        Update server usage statistics from Virtualmin.

        Args:
            server: Server to update

        Returns:
            Result with statistics or error message
        """
        try:
            provisioning_service = VirtualminProvisioningService(server)
            gateway = provisioning_service._get_gateway(server)

            # Get server info
            info_result = gateway.get_server_info()
            if info_result.is_err():
                return Err(f"Failed to get server info: {info_result.unwrap_err()}")

            # Get domain list
            domains_result = gateway.list_domains(name_only=True)
            if domains_result.is_err():
                return Err(f"Failed to list domains: {domains_result.unwrap_err()}")

            domains = domains_result.unwrap()
            domain_count = len(domains) if isinstance(domains, list) else 0

            # Update server statistics
            server.current_domains = domain_count
            server.save(update_fields=["current_domains", "updated_at"])

            stats = {"domain_count": domain_count, "server_info": info_result.unwrap()}

            logger.info(f"📊 [ServerManagement] Updated stats for {server.hostname}: {domain_count} domains")
            return Ok(stats)

        except Exception as e:
            logger.exception(f"Error updating statistics for {server.hostname}: {e}")
            return Err(str(e))


class VirtualminBackupManagementService:
    """
    High-level backup management service for Virtualmin accounts.

    Integrates VirtualminBackupService with PRAHO's job tracking and audit systems.
    """

    def __init__(self, server: VirtualminServer):
        self.server = server

    def create_backup_job(
        self, account: VirtualminAccount, config: BackupConfig | None = None, initiated_by: str = "system"
    ) -> Result[VirtualminProvisioningJob, str]:
        """
        Create and execute backup job for Virtualmin account.

        Args:
            account: Virtualmin account to backup
            backup_type: Type of backup (full, incremental, config_only)
            include_email: Include email data
            include_databases: Include database data
            include_files: Include web files
            include_ssl: Include SSL certificates
            initiated_by: User or system that initiated the backup

        Returns:
            Result with provisioning job or error message
        """
        try:
            # Import here to avoid circular imports
            from .virtualmin_backup_service import BackupConfig, VirtualminBackupService  # noqa: PLC0415

            # Use default config if none provided
            if config is None:
                config = BackupConfig()

            # Create provisioning job
            job = VirtualminProvisioningJob.objects.create(
                operation="backup_domain",
                account=account,
                server=self.server,
                parameters={
                    "backup_type": config.backup_type,
                    "include_email": config.include_email,
                    "include_databases": config.include_databases,
                    "include_files": config.include_files,
                    "include_ssl": config.include_ssl,
                    "initiated_by": initiated_by,
                },
                status="running",
                started_at=timezone.now(),
            )

            # Initialize backup service
            backup_service = VirtualminBackupService(self.server)

            # Execute backup
            backup_result = backup_service.backup_domain(account=account, config=config)

            if backup_result.is_err():
                # Update job with error
                job.status = "failed"
                job.error_message = backup_result.unwrap_err()  # type: ignore[attr-defined]
                job.completed_at = timezone.now()
                job.save()

                return Err(f"Backup failed: {backup_result.unwrap_err()}")

            # Update job with success
            backup_info = backup_result.unwrap()
            job.status = "completed"
            job.response_data = backup_info  # type: ignore[attr-defined]
            job.completed_at = timezone.now()
            job.save()

            logger.info(f"Backup job completed successfully: {job.id}")
            return Ok(job)

        except Exception as e:
            logger.error(f"Backup job creation failed: {e}")
            return Err(f"Backup job failed: {e!s}")

    def create_restore_job(
        self,
        account: VirtualminAccount,
        config: RestoreConfig,
        target_server: VirtualminServer | None = None,
        initiated_by: str = "system",
    ) -> Result[VirtualminProvisioningJob, str]:
        """
        Create and execute restore job for Virtualmin account.

        Args:
            account: Target account for restore
            config: Restore configuration object
            target_server: Target server (defaults to account's server)
            initiated_by: User or system that initiated the restore

        Returns:
            Result with provisioning job or error message
        """
        try:
            # Import here to avoid circular imports
            from .virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415

            target_server = target_server or self.server

            # Create provisioning job
            job = VirtualminProvisioningJob.objects.create(
                operation="restore_domain",
                account=account,
                server=target_server,
                parameters={
                    "backup_id": config.backup_id,
                    "restore_email": config.restore_email,
                    "restore_databases": config.restore_databases,
                    "restore_files": config.restore_files,
                    "restore_ssl": config.restore_ssl,
                    "target_server_id": str(target_server.id),
                    "initiated_by": initiated_by,
                },
                status="running",
                started_at=timezone.now(),
            )

            # Initialize backup service
            backup_service = VirtualminBackupService(target_server)

            # Execute restore
            restore_result = backup_service.restore_domain(account=account, config=config, target_server=target_server)

            if restore_result.is_err():
                # Update job with error
                job.status = "failed"
                job.error_message = restore_result.unwrap_err()  # type: ignore[attr-defined]
                job.completed_at = timezone.now()
                job.save()

                return Err(f"Restore failed: {restore_result.unwrap_err()}")

            # Update job with success
            restore_info = restore_result.unwrap()
            job.status = "completed"
            job.response_data = restore_info  # type: ignore[attr-defined]
            job.completed_at = timezone.now()
            job.save()

            logger.info(f"Restore job completed successfully: {job.id}")
            return Ok(job)

        except Exception as e:
            logger.error(f"Restore job creation failed: {e}")
            return Err(f"Restore job failed: {e!s}")
