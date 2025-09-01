"""
Domain Webhook Handlers - PRAHO Platform
Secure webhook processing for registrar integrations with signature verification.
"""

import json
import logging
from datetime import datetime
from typing import Any

from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.audit.services import AuditContext, DomainsAuditService
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event

from .models import Domain, Registrar
from .services import DomainRegistrarGateway

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class RegistrarWebhookView(View):
    """
    🔐 Secure registrar webhook handler with signature verification

    Handles webhooks from external registrars for domain events:
    - Domain registration completion
    - Domain renewal notifications
    - Domain transfer status updates
    - Domain expiration warnings
    - WHOIS privacy changes
    """

    def post(self, request: HttpRequest, registrar_slug: str) -> JsonResponse:
        """Process incoming webhook from registrar"""
        # Get registrar and validate
        registrar = get_object_or_404(Registrar, name=registrar_slug, status="active")

        # Get client IP for security logging
        client_ip = get_safe_client_ip(request)

        try:
            # Get webhook payload
            payload_body = request.body.decode("utf-8")

            # Verify webhook signature
            signature = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Signature")

            if not self._verify_webhook_signature(registrar, payload_body, signature):
                # Log security event for invalid webhook
                log_security_event(
                    "registrar_webhook_invalid_signature",
                    {
                        "registrar": registrar.name,
                        "client_ip": client_ip,
                        "signature_provided": bool(signature),
                        "payload_size": len(payload_body),
                    },
                    client_ip,
                )

                logger.warning(f"🚨 [Webhook] Invalid signature from {registrar.name} at {client_ip}")
                return JsonResponse({"error": "Invalid signature"}, status=403)

            # Parse webhook payload
            try:
                webhook_data = json.loads(payload_body)
            except json.JSONDecodeError as e:
                logger.error(f"🔥 [Webhook] Invalid JSON from {registrar.name}: {e}")
                return JsonResponse({"error": "Invalid JSON payload"}, status=400)

            # Process webhook event
            event_type = webhook_data.get("event_type", "unknown")
            domain_name = webhook_data.get("domain_name", "")

            # Log successful webhook receipt
            logger.info(f"📩 [Webhook] Received {event_type} for {domain_name} from {registrar.name}")

            # Process the webhook based on event type
            success, message = self._process_webhook_event(registrar, event_type, webhook_data, client_ip)

            if success:
                return JsonResponse(
                    {
                        "status": "success",
                        "message": message,
                        "event_type": event_type,
                        "domain": domain_name,
                    }
                )
            else:
                logger.error(f"🔥 [Webhook] Processing failed: {message}")
                return JsonResponse(
                    {
                        "status": "error",
                        "message": message,
                        "event_type": event_type,
                    },
                    status=400,
                )

        except Exception as e:
            # Log unexpected webhook error
            log_security_event(
                "registrar_webhook_processing_error",
                {
                    "registrar": registrar.name,
                    "client_ip": client_ip,
                    "error": str(e)[:200],
                },
                client_ip,
            )

            logger.exception(f"🔥 [Webhook] Unexpected error processing webhook from {registrar.name}")
            return JsonResponse({"error": "Internal processing error"}, status=500)

    def _verify_webhook_signature(self, registrar: Registrar, payload: str, signature: str | None) -> bool:
        """🔐 Verify webhook signature using registrar's webhook secret"""
        if not signature:
            logger.warning(f"⚠️ [Webhook] No signature provided by {registrar.name}")
            return False

        return DomainRegistrarGateway.verify_webhook_signature(registrar, payload, signature)

    def _process_webhook_event(
        self, registrar: Registrar, event_type: str, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """📋 Process specific webhook event types"""

        domain_name = webhook_data.get("domain_name", "")
        if not domain_name:
            return False, "Missing domain_name in webhook data"

        # Find domain in our system
        try:
            domain = Domain.objects.get(name=domain_name.lower(), registrar=registrar)
        except Domain.DoesNotExist:
            logger.warning(f"⚠️ [Webhook] Domain {domain_name} not found for {registrar.name}")
            return False, f"Domain {domain_name} not found in system"

        # Process based on event type via handler map for fewer returns
        handler_map: dict[str, Any] = {
            "domain.registered": self._handle_domain_registered,
            "domain.renewed": self._handle_domain_renewed,
            "domain.transfer.completed": self._handle_domain_transfer_completed,
            "domain.expiring": self._handle_domain_expiring,
            "domain.expired": self._handle_domain_expired,
            "domain.suspended": self._handle_domain_suspended,
            "whois.privacy.enabled": lambda d, data, ip: self._handle_whois_privacy_changed(d, data, True, ip),
            "whois.privacy.disabled": lambda d, data, ip: self._handle_whois_privacy_changed(d, data, False, ip),
        }
        handler = handler_map.get(event_type)
        if handler is None:
            logger.warning(f"⚠️ [Webhook] Unknown event type: {event_type}")
            return True, f"Event {event_type} acknowledged (no handler)"
        return handler(domain, webhook_data, client_ip)

    def _handle_domain_registered(
        self, domain: Domain, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """✅ Handle domain registration completion"""
        try:
            # Update domain status and details from registrar
            domain.status = "active"
            domain.registrar_domain_id = webhook_data.get("registrar_domain_id", domain.registrar_domain_id)
            domain.epp_code = webhook_data.get("epp_code", domain.epp_code)

            # Update expiration date if provided
            expires_at = webhook_data.get("expires_at")
            if expires_at:
                try:
                    domain.expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                except ValueError:
                    logger.warning(f"⚠️ [Webhook] Invalid expires_at format: {expires_at}")

            # Update nameservers if provided
            nameservers = webhook_data.get("nameservers")
            if nameservers and isinstance(nameservers, list):
                domain.nameservers = nameservers

            domain.save()

            # Log audit event
            DomainsAuditService.log_domain_event(
                event_type="domain_registration_completed",
                domain=domain,
                user=None,
                context=AuditContext(actor_type="system", ip_address=client_ip),
                description=f"Domain registration completed via webhook from {domain.registrar.name}",
            )

            logger.info(f"✅ [Webhook] Domain registration completed: {domain.name}")
            return True, "Domain registration processed successfully"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process domain registration: {e}")
            return False, str(e)

    def _handle_domain_renewed(self, domain: Domain, webhook_data: dict[str, Any], client_ip: str) -> tuple[bool, str]:
        """🔄 Handle domain renewal notification"""
        try:
            # Update expiration date
            expires_at = webhook_data.get("expires_at")
            if expires_at:
                try:
                    domain.expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    domain.renewal_notices_sent = 0  # Reset renewal notices
                    domain.save()

                    # Log audit event
                    DomainsAuditService.log_domain_event(
                        event_type="domain_renewed_webhook",
                        domain=domain,
                        user=None,
                            context=AuditContext(actor_type="system", ip_address=client_ip),
                        description=f"Domain renewal processed via webhook from {domain.registrar.name}",
                    )

                    logger.info(f"🔄 [Webhook] Domain renewed: {domain.name} expires {domain.expires_at}")
                    return True, "Domain renewal processed successfully"

                except ValueError as e:
                    logger.warning(f"⚠️ [Webhook] Invalid expires_at format: {expires_at}")
                    return False, f"Invalid expiration date format: {e}"
            else:
                return False, "Missing expires_at in renewal webhook"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process domain renewal: {e}")
            return False, str(e)

    def _handle_domain_transfer_completed(
        self, domain: Domain, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """📥 Handle domain transfer completion"""
        try:
            # Update domain status
            domain.status = "active"

            # Update registrar domain ID and EPP code if provided
            if "registrar_domain_id" in webhook_data:
                domain.registrar_domain_id = webhook_data["registrar_domain_id"]
            if "epp_code" in webhook_data:
                domain.epp_code = webhook_data["epp_code"]

            domain.save()

            # Log security event for domain transfer
            DomainsAuditService.log_domain_security_event(
                event_type="domain_transfer_completed_webhook",
                domain=domain,
                security_action="transfer_completed",
                security_metadata={
                    "source": "webhook",
                    "registrar": domain.registrar.name,
                    "client_ip": client_ip,
                },
                description=f"Domain transfer completed via webhook from {domain.registrar.name}",
            )

            logger.info(f"📥 [Webhook] Domain transfer completed: {domain.name}")
            return True, "Domain transfer completion processed successfully"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process domain transfer: {e}")
            return False, str(e)

    def _handle_domain_expiring(self, domain: Domain, webhook_data: dict[str, Any], client_ip: str) -> tuple[bool, str]:
        """⚠️ Handle domain expiration warning"""
        try:
            # Log the expiration warning
            days_until_expiry = webhook_data.get("days_until_expiry", "unknown")

            logger.warning(f"⚠️ [Webhook] Domain expiring soon: {domain.name} ({days_until_expiry} days)")

            # Could trigger notification system here
            return True, f"Domain expiration warning processed for {domain.name}"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process expiration warning: {e}")
            return False, str(e)

    def _handle_domain_expired(self, domain: Domain, webhook_data: dict[str, Any], client_ip: str) -> tuple[bool, str]:
        """🔴 Handle domain expiration"""
        try:
            # Update domain status
            domain.status = "expired"
            domain.save()

            # Log audit event
            DomainsAuditService.log_domain_event(
                event_type="domain_expired_webhook",
                domain=domain,
                user=None,
                context=AuditContext(actor_type="system", ip_address=client_ip),
                description=f"Domain expired (webhook notification from {domain.registrar.name})",
            )

            logger.warning(f"🔴 [Webhook] Domain expired: {domain.name}")
            return True, "Domain expiration processed successfully"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process domain expiration: {e}")
            return False, str(e)

    def _handle_domain_suspended(
        self, domain: Domain, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """⏸️ Handle domain suspension"""
        try:
            # Update domain status
            domain.status = "suspended"
            domain.save()

            # Log security event for suspension
            DomainsAuditService.log_domain_security_event(
                event_type="domain_suspended_webhook",
                domain=domain,
                security_action="domain_suspended",
                security_metadata={
                    "source": "webhook",
                    "reason": webhook_data.get("suspension_reason", "Not specified"),
                    "registrar": domain.registrar.name,
                    "client_ip": client_ip,
                },
                description=f"Domain suspended (webhook notification from {domain.registrar.name})",
            )

            logger.warning(f"⏸️ [Webhook] Domain suspended: {domain.name}")
            return True, "Domain suspension processed successfully"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process domain suspension: {e}")
            return False, str(e)

    def _handle_whois_privacy_changed(
        self, domain: Domain, webhook_data: dict[str, Any], privacy_enabled: bool, client_ip: str
    ) -> tuple[bool, str]:
        """🔒 Handle WHOIS privacy status change"""
        try:
            # Update privacy status
            old_privacy = domain.whois_privacy
            domain.whois_privacy = privacy_enabled
            domain.save()

            # Log security event for privacy change
            DomainsAuditService.log_domain_security_event(
                event_type="whois_privacy_changed_webhook",
                domain=domain,
                security_action="whois_privacy_changed",
                security_metadata={
                    "source": "webhook",
                    "old_privacy": old_privacy,
                    "new_privacy": privacy_enabled,
                    "registrar": domain.registrar.name,
                    "client_ip": client_ip,
                },
                description=f"WHOIS privacy {'enabled' if privacy_enabled else 'disabled'} via webhook",
            )

            status = "enabled" if privacy_enabled else "disabled"
            logger.info(f"🔒 [Webhook] WHOIS privacy {status}: {domain.name}")
            return True, f"WHOIS privacy change processed successfully ({status})"

        except Exception as e:
            logger.error(f"🔥 [Webhook] Failed to process WHOIS privacy change: {e}")
            return False, str(e)


@require_http_methods(["GET"])
def webhook_health_check(request: HttpRequest, registrar_slug: str) -> JsonResponse:
    """🏥 Health check endpoint for registrar webhooks"""
    try:
        registrar = get_object_or_404(Registrar, name=registrar_slug, status="active")
        return JsonResponse(
            {
                "status": "healthy",
                "registrar": registrar.display_name,
                "webhook_endpoint_configured": bool(registrar.webhook_endpoint),
                "webhook_secret_configured": bool(registrar.webhook_secret),
            }
        )
    except Exception as e:
        logger.error(f"🔥 [Webhook] Health check failed for {registrar_slug}: {e}")
        return JsonResponse({"status": "unhealthy", "error": str(e)}, status=500)
