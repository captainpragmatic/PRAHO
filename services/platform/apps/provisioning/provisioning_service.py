"""
Provisioning business logic and service management.
Handles service activation, suspension, and infrastructure management.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.provisioning.models import Service

logger = logging.getLogger(__name__)


class ProvisioningService:
    """
    Service activation and provisioning service.
    Handles service lifecycle management and infrastructure provisioning.
    """

    @staticmethod
    def activate_service(service: Service, activation_reason: str = "Service activation") -> Result[bool, str]:
        """
        Activate a single service.

        Args:
            service: Service instance to activate
            activation_reason: Reason for activation (for audit)

        Returns:
            Result with success status or error message
        """
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            AuditService,  # Circular: cross-app  # Deferred: avoids circular import
        )

        try:
            previous_status = service.status

            with transaction.atomic():
                if service.status == "provisioning":
                    service.complete_provisioning()
                else:
                    service.activate()
                service.save(
                    update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"]
                )

                AuditService.log_simple_event(
                    event_type="service_activated",
                    user=None,
                    content_object=service,
                    description=f"Service activated: {activation_reason}",
                    actor_type="system",
                    metadata={
                        "service_id": str(service.id),
                        "previous_status": previous_status,
                        "activation_reason": activation_reason,
                        "activated_at": service.activated_at.isoformat() if service.activated_at else None,
                        "source_app": "provisioning",
                    },
                )

            logger.info(f"✅ [Provisioning] Activated service {service.id} - {activation_reason}")
            return Ok(True)

        except Exception as e:
            error_msg = f"Failed to activate service {service.id}: {e}"
            logger.error(f"🔥 [Provisioning] {error_msg}")
            return Err(error_msg)

    @staticmethod
    def suspend_services_for_customer(customer_id: int, reason: str = "payment_overdue") -> dict[str, Any]:
        """
        Suspend services for customer.

        Args:
            customer_id: Customer ID whose services should be suspended
            reason: Reason for suspension (e.g., 'payment_overdue', 'tos_violation')

        Returns:
            Dictionary with suspension results
        """
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            AuditService,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Service,  # Circular: same-app  # Deferred: avoids circular import
        )

        results: dict[str, Any] = {"success": True, "customer_id": customer_id, "services_suspended": 0, "errors": []}

        try:
            customer = Customer.objects.get(id=customer_id)
            active_services = Service.objects.filter(customer=customer, status="active")

            with transaction.atomic():
                for service in active_services:
                    try:
                        service.suspend(reason=reason)
                        service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                        results["services_suspended"] += 1
                    except Exception as e:
                        results["errors"].append({"service_id": str(service.id), "error": str(e)})

            AuditService.log_simple_event(
                event_type="customer_services_suspended",
                user=None,
                content_object=customer,
                description=f"Suspended {results['services_suspended']} services for customer: {reason}",
                actor_type="system",
                metadata={
                    "customer_id": str(customer.id),
                    "reason": reason,
                    "services_suspended": results["services_suspended"],
                    "source_app": "provisioning",
                },
            )

            logger.info(
                f"⚠️ [Provisioning] Suspended {results['services_suspended']} services "
                f"for customer {customer_id} - {reason}"
            )
            return results

        except Customer.DoesNotExist:
            logger.error(f"🔥 [Provisioning] Customer {customer_id} not found")
            return {"success": False, "error": "Customer not found", "services_suspended": 0}
        except Exception as e:
            logger.error(f"🔥 [Provisioning] Failed to suspend services for customer {customer_id}: {e}")
            return {"success": False, "error": str(e), "services_suspended": 0}

    @staticmethod
    def provision_service(  # noqa: PLR0911, PLR0915  # Complexity: multi-step business logic
        service: Service,
    ) -> dict[str, Any]:  # Complexity: provisioning workflow  # Complexity: multi-step business logic
        """
        Provision a new service after order confirmation.
        This triggers the actual infrastructure setup for the service.
        """
        try:
            logger.info(f"🚀 [Provisioning] Provisioning service {service.id} ({service.service_name})")

            # Update service status and track provisioning attempt
            service.start_provisioning()
            service.last_provisioning_attempt = timezone.now()
            service.provisioning_errors = ""  # Clear previous errors
            service.save(update_fields=["status", "last_provisioning_attempt", "provisioning_errors"])

            logger.info(f"✅ [Provisioning] Service {service.id} provisioning initiated")

            # Check if we have a server assigned and it has API access
            if service.server:
                server_info = f"Server: {service.server.name} ({service.server.control_panel})"
                if not service.server.management_api_url:
                    # Server exists but no API configured
                    error_msg = f"Server {service.server.name} has no API configured for {service.server.control_panel}"
                    logger.warning(f"⚠️ [Provisioning] {error_msg}")
                    service.provisioning_errors = error_msg
                    service.save(update_fields=["provisioning_errors"])

                    return {
                        "status": "pending_manual",
                        "message": f"Manual provisioning required - {error_msg}",
                        "server": server_info,
                        "requires_action": True,
                    }

                # Implement actual provisioning based on control panel type
                if service.server.control_panel == "Virtualmin":
                    try:
                        from .virtualmin_gateway import (  # Circular: same-app  # noqa: PLC0415  # Deferred: avoids circular import
                            VirtualminAuthError,
                            VirtualminConfig,
                            VirtualminGateway,
                            VirtualminQuotaExceededError,
                            VirtualminTransientError,
                        )

                        # Create gateway and test connection
                        config = VirtualminConfig(server=service.server)  # type: ignore[arg-type]
                        gateway = VirtualminGateway(config)

                        logger.info(f"📡 [Provisioning] Testing connection to {service.server.name}")
                        health_result = gateway.test_connection()

                        if health_result.is_err():
                            # REAL INFRASTRUCTURE FAILURE -> FAILED STATUS
                            error_msg = f"Server unreachable: {health_result.unwrap_err()}"
                            logger.error(f"❌ [Provisioning] {error_msg}")
                            service.fail_provisioning()
                            service.provisioning_errors = error_msg
                            service.save(update_fields=["status", "provisioning_errors"])

                            return {"status": "failed", "message": error_msg, "server": server_info}

                        # Server is reachable, but domain creation not implemented yet
                        logger.info(f"📡 [Provisioning] {service.server.name} is healthy - domain creation pending")
                        service.provisioning_errors = "Server accessible - domain creation API pending implementation"
                        service.save(update_fields=["provisioning_errors"])

                        return {
                            "status": "pending_implementation",
                            "message": "Server healthy - domain creation pending implementation",
                            "server": server_info,
                            "gateway_status": "connected",
                        }

                    except (VirtualminAuthError, VirtualminTransientError, VirtualminQuotaExceededError) as api_error:
                        # REAL API/INFRASTRUCTURE FAILURES -> FAILED STATUS
                        error_msg = f"Virtualmin error: {api_error}"
                        logger.error(f"❌ [Provisioning] {error_msg}")
                        service.fail_provisioning()
                        service.provisioning_errors = error_msg
                        service.save(update_fields=["status", "provisioning_errors"])

                        return {
                            "status": "failed",
                            "message": error_msg,
                            "server": server_info,
                            "error_type": type(api_error).__name__,
                        }

                elif service.server.control_panel == "Virtualizor":
                    # VPS provisioning
                    logger.info(f"📡 [Provisioning] Would call VirtualizorGateway for {service.server.name}")
                    service.provisioning_errors = "Virtualizor gateway pending implementation"
                    service.save(update_fields=["provisioning_errors"])

                    return {
                        "status": "pending_implementation",
                        "message": "Virtualizor gateway pending implementation",
                        "server": server_info,
                    }
                else:
                    # Unknown control panel
                    logger.warning(f"⚠️ [Provisioning] Unknown control panel: {service.server.control_panel}")
                    service.provisioning_errors = f"Unknown control panel: {service.server.control_panel}"
                    service.save(update_fields=["provisioning_errors"])

                    return {
                        "status": "pending_manual",
                        "message": f"Unknown control panel type: {service.server.control_panel}",
                        "server": server_info,
                        "requires_action": True,
                    }
            else:
                # No server assigned
                logger.warning(f"⚠️ [Provisioning] Service {service.id} has no server assigned")
                service.provisioning_errors = "No server assigned. Manual server assignment required."
                service.save(update_fields=["provisioning_errors"])

                return {
                    "status": "pending_manual",
                    "message": "No server assigned - manual provisioning required",
                    "requires_action": True,
                }

        except Exception as e:
            error_msg = f"Failed to provision service {service.id}: {e}"
            logger.error(f"🔥 [Provisioning] {error_msg}")

            # Update service status to failed with detailed error info for staff
            service.fail_provisioning()
            service.last_provisioning_attempt = timezone.now()
            service.provisioning_errors = error_msg
            service.save(update_fields=["status", "last_provisioning_attempt", "provisioning_errors"])

            # Log critical error for monitoring/alerting systems
            logger.critical(
                f"💥 [PROVISIONING FAILURE] Service {service.id} ({service.service_name}) failed to provision: {error_msg}"
            )

            return {"status": "failed", "error": error_msg}
