"""
Virtualmin Business Logic Service - PRAHO Platform
High-level service operations for Virtualmin provisioning and management.
"""

from __future__ import annotations

import logging
import secrets
import string
import uuid
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

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
    from apps.provisioning.models import Service

logger = logging.getLogger(__name__)

# Username generation constants
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_UNIQUENESS_ATTEMPTS = 1000


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
                timeout=config_data['timeout'],
                verify_ssl=config_data.get('ssl_verify', target_server.ssl_verify),
                cert_fingerprint=target_server.ssl_cert_fingerprint or config_data.get('pinned_cert_sha256', ''),
            )
            
            self._gateway = VirtualminGateway(config)
            
        return self._gateway
        
    def create_virtualmin_account(
        self,
        service: Service,
        domain: str,
        username: str | None = None,
        password: str | None = None,
        template: str = "Default",
        server: VirtualminServer | None = None
    ) -> Result[VirtualminAccount, str]:
        """
        Create new Virtualmin account for PRAHO service.
        
        Args:
            service: PRAHO service to link
            domain: Primary domain name
            username: Virtualmin username (auto-generated if None)
            password: Account password (auto-generated if None)
            template: Virtualmin template to use
            server: Target server (auto-selected if None)
            
        Returns:
            Result with created VirtualminAccount or error message
        """
        try:
            # Input validation
            domain = VirtualminValidator.validate_domain_name(domain)
            template = VirtualminValidator.validate_template_name(template)
            
            # Auto-generate username if not provided
            if not username:
                username = self._generate_username_from_domain(domain)
            else:
                username = VirtualminValidator.validate_username(username)
                
            # Auto-generate password if not provided
            if not password:
                password = self._generate_secure_password()
            else:
                password = VirtualminValidator.validate_password(password)
                
            # Select server if not provided
            if not server:
                server_result = self._select_best_server()
                if server_result.is_err():
                    return Err(f"Server selection failed: {server_result.unwrap_err()}")
                server = server_result.unwrap()
                
            # Check if domain already exists
            existing_account = VirtualminAccount.objects.filter(domain=domain).first()
            if existing_account:
                return Err(f"Domain {domain} already exists in PRAHO")
                
            # Create account record
            with transaction.atomic():
                account = VirtualminAccount(
                    domain=domain,
                    service=service,
                    server=server,
                    virtualmin_username=username,
                    template_name=template,
                    status="provisioning",
                    praho_customer_id=service.customer.id,
                    praho_service_id=service.id
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
                        "recovery_seed": account.get_recovery_seed()
                    },
                    correlation_id=f"create_domain_{account.id}"
                )
                job.save()
                
            # Execute provisioning
            provisioning_result = self._execute_domain_creation(account, job)
            
            if provisioning_result.is_ok():
                logger.info(
                    f"✅ [VirtualminService] Created account {domain} for customer {service.customer.id}"
                )
                return Ok(account)
            else:
                error_msg = provisioning_result.unwrap_err()
                logger.error(
                    f"❌ [VirtualminService] Failed to create account {domain}: {error_msg}"
                )
                
                # Update account status
                account.status = "error"
                account.status_message = error_msg
                account.save(update_fields=['status', 'status_message', 'updated_at'])
                
                return Err(error_msg)
                
        except ValidationError as e:
            return Err(f"Validation error: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error creating Virtualmin account: {e}")
            return Err(f"Internal error: {e}")
            
    def _execute_domain_creation(
        self, 
        account: VirtualminAccount, 
        job: VirtualminProvisioningJob
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
                "comment": account.get_recovery_seed()  # Store recovery seed
            }
            
            # Add quota limits if specified
            if account.disk_quota_mb:
                params["quota"] = str(account.disk_quota_mb)
                
            if account.bandwidth_quota_mb:
                params["bw-limit"] = str(account.bandwidth_quota_mb)
                
            # Make API call
            result = gateway.call(
                "create-domain",
                params,
                correlation_id=job.correlation_id
            )
            
            if result.is_ok():
                response = result.unwrap()
                
                if response.success:
                    # Track successful domain creation for potential rollback
                    rollback_operations.append({
                        "operation": "delete-domain",
                        "params": {"domain": account.domain},
                        "description": f"Delete domain {account.domain}"
                    })
                    
                    try:
                        # Update account status
                        account.status = "active"
                        account.provisioned_at = timezone.now()
                        account.save(update_fields=['status', 'provisioned_at', 'updated_at'])
                        
                        # Update server stats (track for rollback)
                        old_domain_count = account.server.current_domains
                        account.server.current_domains += 1
                        account.server.save(update_fields=['current_domains', 'updated_at'])
                        
                        rollback_operations.append({
                            "operation": "revert_server_stats",
                            "params": {"domain_count": old_domain_count},
                            "description": f"Revert server domain count to {old_domain_count}"
                        })
                        
                        # Mark job as completed
                        job.mark_completed(response.data, rollback_operations)
                        
                        logger.info(f"✅ [VirtualminService] Successfully created domain {account.domain}")
                        return Ok(response.data)
                        
                    except Exception as db_error:
                        # Database update failed - rollback Virtualmin domain creation
                        logger.error(f"🔥 [VirtualminService] Database update failed for {account.domain}: {db_error}")
                        rollback_result = self._execute_rollback(rollback_operations, gateway, account)
                        if rollback_result.is_err():
                            logger.error(f"🚨 [VirtualminService] CRITICAL: Rollback failed for {account.domain}: {rollback_result.unwrap_err()}")
                        
                        job.mark_failed(f"Database update failed: {db_error}")
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
    
    def _validate_provisioning_preconditions(
        self, 
        account: VirtualminAccount, 
        gateway: VirtualminGateway
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
            health_result = self.health_check_server(account.server)
            if health_result.is_err():
                return Err(f"Server health check failed: {health_result.unwrap_err()}")
            
            # 2. Check server capacity
            if account.server.max_domains and account.server.current_domains >= account.server.max_domains:
                return Err(f"Server {account.server.name} at capacity ({account.server.current_domains}/{account.server.max_domains} domains)")
            
            # 3. Check disk space if quota specified
            if account.disk_quota_mb:
                server_info = health_result.unwrap()
                available_mb = server_info.get('available_disk_mb', 0)
                if available_mb < account.disk_quota_mb:
                    return Err(f"Insufficient disk space: {available_mb}MB available, {account.disk_quota_mb}MB requested")
            
            # 4. Verify domain doesn't already exist on server
            domain_check = gateway.call("list-domains", {"domain": account.domain})
            if domain_check.is_ok() and domain_check.unwrap().success:
                domains = domain_check.unwrap().data.get('domains', [])
                if any(d.get('domain') == account.domain for d in domains):
                    return Err(f"Domain {account.domain} already exists on server")
            
            # 5. Check if username conflicts exist
            user_check = gateway.call("list-users", {"user": account.virtualmin_username})
            if user_check.is_ok() and user_check.unwrap().success:
                users = user_check.unwrap().data.get('users', [])
                if any(u.get('user') == account.virtualmin_username for u in users):
                    return Err(f"Username {account.virtualmin_username} already exists on server")
            
            # 6. Verify template exists
            template_check = gateway.call("list-templates")
            if template_check.is_ok() and template_check.unwrap().success:
                templates = template_check.unwrap().data.get('templates', [])
                if not any(t.get('name') == account.template_name for t in templates):
                    return Err(f"Template {account.template_name} not found on server")
            
            logger.info(f"✅ [VirtualminService] All preconditions validated for {account.domain}")
            return Ok(True)
            
        except Exception as e:
            logger.exception(f"🔥 [VirtualminService] Validation error for {account.domain}: {e}")
            return Err(f"Validation error: {e}")
    
    def _execute_rollback(
        self, 
        rollback_operations: list[dict[str, Any]], 
        gateway: VirtualminGateway,
        account: VirtualminAccount
    ) -> Result[bool, str]:
        """
        Execute rollback operations in reverse order (Phase 2).
        
        Args:
            rollback_operations: List of operations to rollback
            gateway: Virtualmin gateway for API calls
            account: Account being rolled back
            
        Returns:
            Result indicating rollback success/failure
        """
        try:
            logger.warning(f"⚠️ [VirtualminService] Starting rollback for {account.domain}")
            
            # Execute rollback operations in reverse order
            for operation in reversed(rollback_operations):
                try:
                    if operation["operation"] == "delete-domain":
                        result = gateway.call("delete-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            logger.error(f"🔥 [VirtualminService] Failed to rollback domain deletion: {operation}")
                            
                    elif operation["operation"] == "revert_server_stats":
                        account.server.current_domains = operation["params"]["domain_count"]
                        account.server.save(update_fields=['current_domains', 'updated_at'])
                        
                    logger.info(f"✅ [VirtualminService] Rolled back: {operation['description']}")
                    
                except Exception as op_error:
                    logger.error(f"🔥 [VirtualminService] Rollback operation failed: {operation['description']} - {op_error}")
                    # Continue with other rollback operations even if one fails
            
            # Update account status to failed
            account.status = "error"
            account.status_message = "Provisioning failed - rollback executed"
            account.save(update_fields=['status', 'status_message', 'updated_at'])
            
            logger.warning(f"⚠️ [VirtualminService] Rollback completed for {account.domain}")
            return Ok(True)
            
        except Exception as e:
            logger.exception(f"🚨 [VirtualminService] CRITICAL: Rollback execution failed for {account.domain}: {e}")
            return Err(f"Rollback execution failed: {e}")
            
    def suspend_account(self, account: VirtualminAccount, reason: str = "") -> Result[bool, str]:
        """
        Suspend Virtualmin account.
        
        Args:
            account: VirtualminAccount to suspend
            reason: Reason for suspension
            
        Returns:
            Result with success status or error message
        """
        try:
            if account.status == "suspended":
                return Ok(True)  # Already suspended
                
            gateway = self._get_gateway(account.server)
            
            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="suspend_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain, "reason": reason},
                correlation_id=f"suspend_domain_{account.id}"
            )
            job.save()
            job.mark_started()
            
            # Make API call
            result = gateway.call(
                "disable-domain",
                {"domain": account.domain},
                correlation_id=job.correlation_id
            )
            
            if result.is_ok():
                response = result.unwrap()
                
                if response.success:
                    account.status = "suspended"
                    account.status_message = reason
                    account.save(update_fields=['status', 'status_message', 'updated_at'])
                    
                    job.mark_completed(response.data)
                    
                    logger.info(f"✅ [VirtualminService] Suspended account {account.domain}")
                    return Ok(True)
                else:
                    error_msg = response.data.get("error", "Suspension failed")
                    job.mark_failed(error_msg, response.data)
                    return Err(error_msg)
                    
            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg)
                return Err(error_msg)
                
        except Exception as e:
            logger.exception(f"Error suspending account {account.domain}: {e}")
            return Err(str(e))
            
    def unsuspend_account(self, account: VirtualminAccount) -> Result[bool, str]:
        """
        Unsuspend (reactivate) Virtualmin account.
        
        Args:
            account: VirtualminAccount to unsuspend
            
        Returns:
            Result with success status or error message
        """
        try:
            if account.status == "active":
                return Ok(True)  # Already active
                
            gateway = self._get_gateway(account.server)
            
            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="unsuspend_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain},
                correlation_id=f"unsuspend_domain_{account.id}"
            )
            job.save()
            job.mark_started()
            
            # Make API call
            result = gateway.call(
                "enable-domain",
                {"domain": account.domain},
                correlation_id=job.correlation_id
            )
            
            if result.is_ok():
                response = result.unwrap()
                
                if response.success:
                    account.status = "active"
                    account.status_message = ""
                    account.save(update_fields=['status', 'status_message', 'updated_at'])
                    
                    job.mark_completed(response.data)
                    
                    logger.info(f"✅ [VirtualminService] Unsuspended account {account.domain}")
                    return Ok(True)
                else:
                    error_msg = response.data.get("error", "Unsuspension failed")
                    job.mark_failed(error_msg, response.data)
                    return Err(error_msg)
                    
            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg)
                return Err(error_msg)
                
        except Exception as e:
            logger.exception(f"Error unsuspending account {account.domain}: {e}")
            return Err(str(e))
            
    def delete_account(self, account: VirtualminAccount) -> Result[bool, str]:
        """
        Delete Virtualmin account permanently.
        
        Args:
            account: VirtualminAccount to delete
            
        Returns:
            Result with success status or error message
        """
        try:
            gateway = self._get_gateway(account.server)
            
            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="delete_domain",
                server=account.server,
                account=account,
                parameters={"domain": account.domain},
                correlation_id=f"delete_domain_{account.id}"
            )
            job.save()
            job.mark_started()
            
            # Make API call
            result = gateway.call(
                "delete-domain",
                {"domain": account.domain},
                correlation_id=job.correlation_id
            )
            
            if result.is_ok():
                response = result.unwrap()
                
                if response.success:
                    # Update server stats
                    account.server.current_domains = max(0, account.server.current_domains - 1)
                    account.server.save(update_fields=['current_domains', 'updated_at'])
                    
                    # Mark account as terminated (don't delete for audit trail)
                    account.status = "terminated"
                    account.save(update_fields=['status', 'updated_at'])
                    
                    job.mark_completed(response.data)
                    
                    logger.info(f"✅ [VirtualminService] Deleted account {account.domain}")
                    return Ok(True)
                else:
                    error_msg = response.data.get("error", "Deletion failed")
                    job.mark_failed(error_msg, response.data)
                    return Err(error_msg)
                    
            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg)
                return Err(error_msg)
                
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
        available_servers = VirtualminServer.objects.filter(
            status="active"
        ).exclude(
            current_domains__gte=models.F('max_domains')
        ).order_by('current_domains')  # Prefer servers with lower load
        
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
        base = domain.split('.')[0]
        username = ''.join(c for c in base if c.isalnum())
        
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
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend([secrets.choice(all_chars) for _ in range(length - 4)])
            
        # Shuffle the password list
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
        
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
                VirtualminDriftRecord.objects.create(
                    account=account,
                    drift_type="status_mismatch",
                    praho_state={"status": account.status, "domain": account.domain},
                    virtualmin_state=virtualmin_data,
                    drift_description="; ".join(drift_detected),
                    resolution_action="logged_for_review"
                )
                
                logger.warning(
                    f"🔍 [VirtualminService] Drift detected for {account.domain}: {drift_detected}"
                )
                
            return Ok({
                "drift_detected": drift_detected,
                "virtualmin_state": virtualmin_data,
                "praho_state": {"status": account.status, "domain": account.domain}
            })
            
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
                return Ok({
                    "drift_detected": drift_detected,
                    "message": "Drift detected but force=False. Use force=True to apply corrections.",
                    "praho_state": sync_data["praho_state"],
                    "virtualmin_state": sync_data["virtualmin_state"]
                })
                
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
            VirtualminDriftRecord.objects.create(
                account=account,
                drift_type="praho_state_enforced",
                praho_state=sync_data["praho_state"],
                virtualmin_state=sync_data["virtualmin_state"],
                drift_description=f"Enforced PRAHO state: {actions_taken}",
                resolution_action="praho_state_enforced"
            )
            
            logger.warning(
                f"🚨 [VirtualminService] Enforced PRAHO state for {account.domain}: {actions_taken}"
            )
            
            return Ok({
                "actions_taken": actions_taken,
                "drift_resolved": drift_detected,
                "enforcement_timestamp": timezone.now().isoformat()
            })
            
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
                server.save(update_fields=['last_health_check', 'health_check_error', 'updated_at'])
                
                logger.info(f"✅ [ServerManagement] Health check passed for {server.hostname}")
                return Ok(health_data)
            else:
                error_msg = result.unwrap_err()
                
                # Update server with error and mark as failed
                server.last_health_check = timezone.now()
                server.health_check_error = error_msg
                server.status = "failed"
                server.save(update_fields=['last_health_check', 'health_check_error', 'status', 'updated_at'])
                
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
            server.save(update_fields=['current_domains', 'updated_at'])
            
            stats = {
                "domain_count": domain_count,
                "server_info": info_result.unwrap()
            }
            
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
        self,
        account: VirtualminAccount,
        config: BackupConfig | None = None,
        initiated_by: str = "system"
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
            from .virtualmin_backup_service import VirtualminBackupService
            
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
                    "initiated_by": initiated_by
                },
                status="running",
                started_at=timezone.now()
            )
            
            # Initialize backup service
            backup_service = VirtualminBackupService(self.server)
            
            # Execute backup
            backup_result = backup_service.backup_domain(
                account=account,
                config=config
            )
            
            if backup_result.is_err():
                # Update job with error
                job.status = "failed"
                job.error_message = backup_result.unwrap_err()
                job.completed_at = timezone.now()
                job.save()
                
                return Err(f"Backup failed: {backup_result.unwrap_err()}")
                
            # Update job with success
            backup_info = backup_result.unwrap()
            job.status = "completed"
            job.response_data = backup_info
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
        initiated_by: str = "system"
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
            from .virtualmin_backup_service import VirtualminBackupService
            
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
                    "initiated_by": initiated_by
                },
                status="running",
                started_at=timezone.now()
            )
            
            # Initialize backup service
            backup_service = VirtualminBackupService(target_server)
            
            # Execute restore
            restore_result = backup_service.restore_domain(
                account=account,
                config=config,
                target_server=target_server
            )
            
            if restore_result.is_err():
                # Update job with error
                job.status = "failed"
                job.error_message = restore_result.unwrap_err()
                job.completed_at = timezone.now()
                job.save()
                
                return Err(f"Restore failed: {restore_result.unwrap_err()}")
                
            # Update job with success
            restore_info = restore_result.unwrap()
            job.status = "completed"
            job.response_data = restore_info
            job.completed_at = timezone.now()
            job.save()
            
            logger.info(f"Restore job completed successfully: {job.id}")
            return Ok(job)
            
        except Exception as e:
            logger.error(f"Restore job creation failed: {e}")
            return Err(f"Restore job failed: {e!s}")
