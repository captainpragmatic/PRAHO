"""
Provisioning business logic and service management.
Handles service activation, suspension, and infrastructure management.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.billing.models import Invoice
    from apps.provisioning.models import Service

logger = logging.getLogger(__name__)


class ProvisioningService:
    """
    Service activation and provisioning service.
    Handles service lifecycle management and infrastructure provisioning.
    """

    @staticmethod
    def activate_service(service: Service, activation_reason: str = "Service activation") -> Result[bool, str]:
        """Activate a single service"""
        try:
            logger.info(f"⚙️ [Provisioning] Activating service {service.id} - {activation_reason}")
            # TODO: Implement actual service activation
            return Ok(True)
        except Exception as e:
            error_msg = f"Failed to activate service {service.id}: {e}"
            logger.error(f"🔥 [Provisioning] {error_msg}")
            return Err(error_msg)

    @staticmethod
    def activate_services_for_invoice(invoice: Invoice | None) -> None:
        """Activate services when invoice is paid"""
        if invoice is None:
            logger.warning("⚠️ [Provisioning] Cannot activate services for None invoice")
            return
        logger.info(f"⚙️ [Provisioning] Would activate services for paid invoice {invoice.number}")
        # TODO: Implement actual service activation

    @staticmethod
    def suspend_services_for_customer(customer_id: int, reason: str = "payment_overdue") -> None:
        """Suspend services for customer"""
        logger.info(f"⚙️ [Provisioning] Would suspend services for customer {customer_id} - {reason}")
        # TODO: Implement service suspension

    @staticmethod
    def reactivate_services_for_customer(customer_id: int, reason: str = "payment_received") -> None:
        """Reactivate suspended services"""
        logger.info(f"⚙️ [Provisioning] Would reactivate services for customer {customer_id} - {reason}")
        # TODO: Implement service reactivation

    @staticmethod
    def provision_service(service: Service) -> dict[str, str]:
        """
        Provision a new service after order confirmation.
        This triggers the actual infrastructure setup for the service.
        """
        from django.utils import timezone

        try:
            logger.info(f"🚀 [Provisioning] Provisioning service {service.id} ({service.service_name})")

            # Update service status and track provisioning attempt
            service.status = 'provisioning'
            service.last_provisioning_attempt = timezone.now()
            service.provisioning_errors = ''  # Clear previous errors
            service.save(update_fields=['status', 'last_provisioning_attempt', 'provisioning_errors'])

            logger.info(f"✅ [Provisioning] Service {service.id} provisioning initiated")

            # Check if we have a server assigned and it has API access
            if service.server:
                server_info = f"Server: {service.server.name} ({service.server.control_panel})"
                if not hasattr(service.server, 'api_url') or not service.server.api_url:
                    # Server exists but no API configured
                    error_msg = f"Server {service.server.name} has no API configured for {service.server.control_panel}"
                    logger.warning(f"⚠️ [Provisioning] {error_msg}")
                    service.provisioning_errors = error_msg
                    service.save(update_fields=['provisioning_errors'])

                    return {
                        'status': 'pending_manual',
                        'message': f'Manual provisioning required - {error_msg}',
                        'server': server_info,
                        'requires_action': True
                    }

                # Implement actual provisioning based on control panel type
                if service.server.control_panel == 'Virtualmin':
                    # Simulate Virtualmin provisioning attempt
                    # In production, this would call VirtualminGateway
                    try:
                        # Examples of when provisioning would FAIL:
                        # - Virtualmin server down/unreachable
                        # - Server disk full/out of space
                        # - Server overloaded/not responding
                        # - Virtualmin service not running
                        # - API authentication failure
                        # - Domain already exists on server
                        # - Username already taken
                        # - Quota/limits exceeded
                        # - Network timeout reaching server
                        # - Invalid domain name format

                        # Use actual VirtualminGateway
                        from .virtualmin_gateway import VirtualminGateway, VirtualminConfig
                        from .virtualmin_gateway import (
                            VirtualminAuthError,
                            VirtualminTransientError,
                            VirtualminConflictExistsError,
                            VirtualminQuotaExceededError
                        )

                        # Create gateway and test connection
                        config = VirtualminConfig(server=service.server)
                        gateway = VirtualminGateway(config)

                        logger.info(f"📡 [Provisioning] Testing connection to {service.server.name}")
                        health_result = gateway.test_connection()

                        if health_result.is_err():
                            # REAL INFRASTRUCTURE FAILURE -> FAILED STATUS
                            error_msg = f"Server unreachable: {health_result.unwrap_err()}"
                            logger.error(f"❌ [Provisioning] {error_msg}")
                            service.status = 'failed'
                            service.provisioning_errors = error_msg
                            service.save(update_fields=['status', 'provisioning_errors'])

                            return {
                                'status': 'failed',
                                'message': error_msg,
                                'server': server_info
                            }

                        # Server is reachable, but domain creation not implemented yet
                        logger.info(f"📡 [Provisioning] {service.server.name} is healthy - domain creation pending")
                        service.provisioning_errors = "Server accessible - domain creation API pending implementation"
                        service.save(update_fields=['provisioning_errors'])

                        return {
                            'status': 'pending_implementation',
                            'message': 'Server healthy - domain creation pending implementation',
                            'server': server_info,
                            'gateway_status': 'connected'
                        }

                    except (VirtualminAuthError, VirtualminTransientError, VirtualminQuotaExceededError) as api_error:
                        # REAL API/INFRASTRUCTURE FAILURES -> FAILED STATUS
                        error_msg = f"Virtualmin error: {api_error}"
                        logger.error(f"❌ [Provisioning] {error_msg}")
                        service.status = 'failed'
                        service.provisioning_errors = error_msg
                        service.save(update_fields=['status', 'provisioning_errors'])

                        return {
                            'status': 'failed',
                            'message': error_msg,
                            'server': server_info,
                            'error_type': type(api_error).__name__
                        }

                elif service.server.control_panel == 'Virtualizor':
                    # VPS provisioning
                    logger.info(f"📡 [Provisioning] Would call VirtualizorGateway for {service.server.name}")
                    service.provisioning_errors = "Virtualizor gateway pending implementation"
                    service.save(update_fields=['provisioning_errors'])

                    return {
                        'status': 'pending_implementation',
                        'message': 'Virtualizor gateway pending implementation',
                        'server': server_info
                    }
                else:
                    # Unknown control panel
                    logger.warning(f"⚠️ [Provisioning] Unknown control panel: {service.server.control_panel}")
                    service.provisioning_errors = f"Unknown control panel: {service.server.control_panel}"
                    service.save(update_fields=['provisioning_errors'])

                    return {
                        'status': 'pending_manual',
                        'message': f'Unknown control panel type: {service.server.control_panel}',
                        'server': server_info,
                        'requires_action': True
                    }
            else:
                # No server assigned
                logger.warning(f"⚠️ [Provisioning] Service {service.id} has no server assigned")
                service.provisioning_errors = "No server assigned. Manual server assignment required."
                service.save(update_fields=['provisioning_errors'])

                return {
                    'status': 'pending_manual',
                    'message': 'No server assigned - manual provisioning required',
                    'requires_action': True
                }

        except Exception as e:
            error_msg = f"Failed to provision service {service.id}: {e}"
            logger.error(f"🔥 [Provisioning] {error_msg}")

            # Update service status to failed with detailed error info for staff
            service.status = 'failed'
            service.last_provisioning_attempt = timezone.now()
            service.provisioning_errors = error_msg
            service.save(update_fields=['status', 'last_provisioning_attempt', 'provisioning_errors'])

            # Log critical error for monitoring/alerting systems
            logger.critical(f"💥 [PROVISIONING FAILURE] Service {service.id} ({service.service_name}) failed to provision: {error_msg}")

            return {
                'status': 'failed',
                'error': error_msg
            }
