# OUTBOUND_HTTP_MIGRATION: pending  # noqa: ERA001
"""
Email Webhook Handlers for PRAHO Platform
Process delivery events from email service providers (AWS SES, SendGrid, Mailgun).

Supports:
- AWS SES SNS notifications (bounce, complaint, delivery)
- SendGrid Event Webhook
- Mailgun Webhooks
- Anymail unified webhook (recommended)

Security:
- Signature validation for all providers
- Rate limiting
- Audit logging
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request
from apps.common.validators import log_security_event
from apps.notifications.services import EmailPreferenceService, EmailService

_HTTP_OK = 200

SNS_CONFIRMATION_POLICY = OutboundPolicy(
    name="sns_confirmation",
    allowed_domains=frozenset({"amazonaws.com"}),
    allow_redirects=True,
    max_redirects=2,
    timeout_seconds=10.0,
)

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class AnymailWebhookView(View):
    """
    Unified webhook handler for Anymail-supported providers.

    This view handles delivery events from any ESP configured with Anymail.
    It processes the standardized Anymail tracking signals.

    URL: /webhooks/email/anymail/
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle Anymail webhook POST requests."""
        try:
            # Validate webhook signature
            if not self._validate_webhook_signature(request):
                log_security_event(
                    "email_webhook_invalid_signature",
                    {"path": request.path, "remote_addr": request.META.get("REMOTE_ADDR")},
                )
                return HttpResponse("Invalid signature", status=403)

            # Process Anymail events via signals
            # Anymail automatically processes webhooks and emits Django signals
            # We just need to acknowledge receipt

            return HttpResponse("OK", status=200)

        except Exception as e:
            logger.exception(f"Anymail webhook error: {e}")
            return HttpResponse("Error", status=500)

    def _validate_webhook_signature(self, request: HttpRequest) -> bool:
        """Validate Anymail webhook signature."""
        webhook_secret = getattr(settings, "ANYMAIL", {}).get("WEBHOOK_SECRET")

        # In production, require webhook secret to be configured
        if not webhook_secret:
            if not getattr(settings, "DEBUG", False):
                logger.error("Webhook secret not configured in production - rejecting request")
                return False
            # Development mode - allow unsigned requests with warning
            logger.warning("Webhook secret not configured - accepting unsigned request (dev mode only)")
            return True

        # Anymail uses basic auth or signature depending on ESP
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Basic "):
            # Basic auth - compare with secret
            try:
                credentials = base64.b64decode(auth_header[6:]).decode()
                if credentials.endswith(f":{webhook_secret}"):
                    return True
            except (binascii.Error, UnicodeDecodeError, ValueError):
                logger.debug("Invalid basic auth payload in Anymail webhook signature")

        return False


@method_decorator(csrf_exempt, name="dispatch")
class SESWebhookView(View):
    """
    AWS SES SNS Notification Handler.

    NOTE: This view is provided for direct SES integration WITHOUT Anymail.
    If using Anymail with SES backend, use AnymailWebhookView instead,
    which handles events via Anymail's tracking signals.

    Handles:
    - Bounce notifications (hard/soft)
    - Complaint notifications (spam reports)
    - Delivery confirmations

    URL: /webhooks/email/ses/
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle AWS SES SNS notifications."""
        try:
            # Parse SNS message
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return HttpResponse("Invalid JSON", status=400)

            # Verify SNS signature before any processing
            if not self._validate_sns_signature(data):
                log_security_event(
                    "email_webhook_invalid_signature",
                    {"provider": "ses", "remote_addr": request.META.get("REMOTE_ADDR")},
                )
                return HttpResponse("Forbidden", status=403)

            message_type = data.get("Type")

            # Handle SNS subscription confirmation
            if message_type == "SubscriptionConfirmation":
                return self._handle_subscription_confirmation(data)

            # Handle notification
            if message_type == "Notification":
                return self._handle_notification(data)

            return HttpResponse("OK", status=200)

        except Exception as e:
            logger.exception(f"SES webhook error: {e}")
            return HttpResponse("Error", status=500)

    def _validate_sns_signature(self, data: dict[str, Any]) -> bool:
        """Validate AWS SNS message signature.

        Returns True if the signature is valid or can be accepted, False otherwise.
        In DEBUG mode, accepts unsigned messages for dev convenience — matching the
        pattern used by the SendGrid and Mailgun handlers.

        See: https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
        """
        # In DEBUG mode, bypass signature check for unsigned messages (dev convenience)
        if getattr(settings, "DEBUG", False) and not data.get("Signature"):
            logger.warning("SES webhook: accepting unsigned SNS message (DEBUG mode)")
            return True

        # Pre-flight checks: version, cert URL validity, non-empty signature
        if not self._sns_preflight_checks(data):
            return False

        # Build canonical message and verify cryptographic signature
        return self._sns_verify_crypto(data)

    def _sns_preflight_checks(self, data: dict[str, Any]) -> bool:
        """Validate SNS header fields before attempting crypto verification."""
        if data.get("SignatureVersion") != "1":
            logger.warning("SES webhook: unsupported SignatureVersion: %s", data.get("SignatureVersion"))
            return False

        signing_cert_url = data.get("SigningCertURL", "")
        parsed = urlparse(signing_cert_url)
        cert_url_ok = parsed.scheme == "https" and bool(parsed.hostname) and parsed.hostname.endswith(".amazonaws.com")
        if not cert_url_ok:
            logger.warning("SES webhook: invalid SigningCertURL: %s", signing_cert_url)
            return False

        if not data.get("Signature", ""):
            logger.warning("SES webhook: empty signature")
            return False

        return True

    def _sns_build_canonical_message(self, data: dict[str, Any]) -> str:
        """Build the canonical string to verify per the AWS SNS signing specification."""
        message_type = data.get("Type", "")
        if message_type == "Notification":
            candidate_fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
        else:
            # SubscriptionConfirmation and UnsubscribeConfirmation
            candidate_fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

        canonical_parts: list[str] = []
        for field in candidate_fields:
            value = data.get(field)
            if value is not None:
                canonical_parts.append(field)
                canonical_parts.append(str(value))
        return "\n".join(canonical_parts) + "\n"

    def _sns_verify_crypto(self, data: dict[str, Any]) -> bool:
        """Fetch the signing cert and verify the RSA-SHA1 signature."""
        signing_cert_url = data.get("SigningCertURL", "")
        signature_b64 = data.get("Signature", "")
        canonical_message = self._sns_build_canonical_message(data)
        try:
            cert_response = safe_request("GET", signing_cert_url, timeout=10)
            if not cert_response or cert_response.status_code != _HTTP_OK:
                logger.warning("SES webhook: failed to fetch signing certificate from %s", signing_cert_url)
                return False

            cert = load_pem_x509_certificate(cert_response.content)
            signature = base64.b64decode(signature_b64)

            cert.public_key().verify(
                signature,
                canonical_message.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA1(),  # noqa: S303  — AWS SNS uses SHA1 for signature v1
            )
            return True
        except Exception:
            logger.warning("SES webhook: signature verification failed", exc_info=True)
            return False

    def _handle_subscription_confirmation(self, data: dict[str, Any]) -> HttpResponse:
        """Handle SNS subscription confirmation."""
        subscribe_url = data.get("SubscribeURL")
        if subscribe_url:
            # Auto-confirm subscription — domain/SSRF validation handled by SNS_CONFIRMATION_POLICY
            try:
                safe_request("GET", subscribe_url, policy=SNS_CONFIRMATION_POLICY)
                logger.info("✅ [SNS] Subscription confirmed")
            except OutboundSecurityError as e:
                logger.warning(f"⚠️ [SNS] Rejected SubscribeURL: {e}")
                return HttpResponse("Invalid SubscribeURL", status=400)
            except Exception as e:
                logger.error(f"🔥 [SNS] Failed to confirm subscription: {e}")

        return HttpResponse("OK", status=200)

    def _handle_notification(self, data: dict[str, Any]) -> HttpResponse:
        """Handle SES notification."""
        try:
            message = json.loads(data.get("Message", "{}"))
        except json.JSONDecodeError:
            return HttpResponse("Invalid message JSON", status=400)

        notification_type = message.get("notificationType")

        if notification_type == "Bounce":
            self._handle_bounce(message)
        elif notification_type == "Complaint":
            self._handle_complaint(message)
        elif notification_type == "Delivery":
            self._handle_delivery(message)

        return HttpResponse("OK", status=200)

    def _handle_bounce(self, message: dict[str, Any]) -> None:
        """Handle SES bounce notification."""
        bounce = message.get("bounce", {})
        bounce_type = bounce.get("bounceType")
        bounced_recipients = bounce.get("bouncedRecipients", [])

        for recipient in bounced_recipients:
            email = recipient.get("emailAddress")
            if email:
                event_type = "bounced" if bounce_type == "Permanent" else "soft_bounced"
                EmailService.handle_delivery_event(
                    event_type=event_type,
                    message_id=message.get("mail", {}).get("messageId", ""),
                    recipient=email,
                    metadata={
                        "bounce_type": bounce_type,
                        "bounce_sub_type": bounce.get("bounceSubType"),
                        "diagnostic_code": recipient.get("diagnosticCode"),
                    },
                )

        logger.info(f"Processed SES bounce for {len(bounced_recipients)} recipients")

    def _handle_complaint(self, message: dict[str, Any]) -> None:
        """Handle SES complaint notification."""
        complaint = message.get("complaint", {})
        complained_recipients = complaint.get("complainedRecipients", [])

        for recipient in complained_recipients:
            email = recipient.get("emailAddress")
            if email:
                EmailService.handle_delivery_event(
                    event_type="complained",
                    message_id=message.get("mail", {}).get("messageId", ""),
                    recipient=email,
                    metadata={
                        "complaint_type": complaint.get("complaintFeedbackType"),
                    },
                )

        logger.info(f"Processed SES complaint for {len(complained_recipients)} recipients")

    def _handle_delivery(self, message: dict[str, Any]) -> None:
        """Handle SES delivery confirmation."""
        delivery = message.get("delivery", {})
        recipients = delivery.get("recipients", [])

        for email in recipients:
            EmailService.handle_delivery_event(
                event_type="delivered",
                message_id=message.get("mail", {}).get("messageId", ""),
                recipient=email,
                timestamp=delivery.get("timestamp"),
            )

        logger.info(f"Processed SES delivery for {len(recipients)} recipients")


@method_decorator(csrf_exempt, name="dispatch")
class SendGridWebhookView(View):
    """
    SendGrid Event Webhook Handler.

    NOTE: This view is provided for direct SendGrid integration WITHOUT Anymail.
    If using Anymail with SendGrid backend, use AnymailWebhookView instead.

    Handles:
    - delivered, bounce, deferred
    - open, click
    - spamreport, unsubscribe, dropped

    URL: /webhooks/email/sendgrid/
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle SendGrid webhook events."""
        try:
            # Validate signature
            if not self._validate_signature(request):
                log_security_event(
                    "email_webhook_invalid_signature",
                    {"provider": "sendgrid", "remote_addr": request.META.get("REMOTE_ADDR")},
                )
                return HttpResponse("Invalid signature", status=403)

            # Parse events
            try:
                events = json.loads(request.body)
            except json.JSONDecodeError:
                return HttpResponse("Invalid JSON", status=400)

            if not isinstance(events, list):
                events = [events]

            for event in events:
                self._process_event(event)

            return HttpResponse("OK", status=200)

        except Exception as e:
            logger.exception(f"SendGrid webhook error: {e}")
            return HttpResponse("Error", status=500)

    def _validate_signature(self, request: HttpRequest) -> bool:
        """Validate SendGrid webhook signature."""
        webhook_key = getattr(settings, "ANYMAIL", {}).get("SENDGRID_WEBHOOK_VERIFICATION_KEY")
        if not webhook_key:
            if not getattr(settings, "DEBUG", False):
                logger.error("SendGrid webhook key not configured in production - rejecting")
                return False
            logger.warning("SendGrid webhook key not configured - accepting unsigned (dev mode)")
            return True

        signature = request.META.get("HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE")
        timestamp = request.META.get("HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP")

        if not signature or not timestamp:
            return False

        # Verify signature
        payload = timestamp + request.body.decode()
        expected = hmac.new(webhook_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

        return hmac.compare_digest(signature, expected)

    def _process_event(self, event: dict[str, Any]) -> None:
        """Process a single SendGrid event."""
        event_type = event.get("event")
        email = event.get("email")
        sg_message_id = event.get("sg_message_id", "")

        event_mapping = {
            "delivered": "delivered",
            "bounce": "bounced",
            "deferred": "soft_bounced",
            "spamreport": "complained",
            "open": "opened",
            "click": "clicked",
        }

        if event_type in event_mapping:
            EmailService.handle_delivery_event(
                event_type=event_mapping[event_type],
                message_id=sg_message_id,
                recipient=email,  # type: ignore[arg-type]
                timestamp=event.get("timestamp"),
                metadata={
                    "event": event_type,
                    "reason": event.get("reason"),
                    "url": event.get("url"),
                },
            )


@method_decorator(csrf_exempt, name="dispatch")
class MailgunWebhookView(View):
    """
    Mailgun Webhook Handler.

    NOTE: This view is provided for direct Mailgun integration WITHOUT Anymail.
    If using Anymail with Mailgun backend, use AnymailWebhookView instead.

    Handles:
    - delivered, failed, bounced
    - opened, clicked
    - complained, unsubscribed

    URL: /webhooks/email/mailgun/
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle Mailgun webhook events."""
        try:
            # Validate signature
            if not self._validate_signature(request):
                log_security_event(
                    "email_webhook_invalid_signature",
                    {"provider": "mailgun", "remote_addr": request.META.get("REMOTE_ADDR")},
                )
                return HttpResponse("Invalid signature", status=403)

            # Parse event data
            event_data = request.POST.get("event-data")
            if event_data:
                try:
                    data = json.loads(event_data)
                except json.JSONDecodeError:
                    data = dict(request.POST)
            else:
                data = dict(request.POST)

            self._process_event(data)

            return HttpResponse("OK", status=200)

        except Exception as e:
            logger.exception(f"Mailgun webhook error: {e}")
            return HttpResponse("Error", status=500)

    def _validate_signature(self, request: HttpRequest) -> bool:
        """Validate Mailgun webhook signature."""
        api_key = getattr(settings, "ANYMAIL", {}).get("MAILGUN_API_KEY")
        if not api_key:
            if not getattr(settings, "DEBUG", False):
                logger.error("Mailgun API key not configured in production - rejecting")
                return False
            logger.warning("Mailgun API key not configured - accepting unsigned (dev mode)")
            return True

        timestamp = request.POST.get("timestamp", "")
        token = request.POST.get("token", "")
        signature = request.POST.get("signature", "")

        if not all([timestamp, token, signature]):
            return False

        # Verify signature
        expected = hmac.new(api_key.encode(), f"{timestamp}{token}".encode(), hashlib.sha256).hexdigest()

        return hmac.compare_digest(signature, expected)

    def _process_event(self, data: dict[str, Any]) -> None:
        """Process a Mailgun event."""
        event_type = data.get("event")
        recipient = data.get("recipient")
        message_id = data.get("Message-Id", data.get("message-id", ""))

        event_mapping = {
            "delivered": "delivered",
            "failed": "bounced",
            "bounced": "bounced",
            "complained": "complained",
            "opened": "opened",
            "clicked": "clicked",
        }

        if event_type in event_mapping and recipient:
            EmailService.handle_delivery_event(
                event_type=event_mapping[event_type],
                message_id=message_id,
                recipient=recipient,
                timestamp=data.get("timestamp"),
                metadata={
                    "event": event_type,
                    "reason": data.get("reason"),
                    "error": data.get("error"),
                },
            )


@method_decorator(csrf_exempt, name="dispatch")
class UnsubscribeView(View):
    """
    Handle email unsubscribe requests.

    URL: /email/unsubscribe/
    """

    def get(self, request: HttpRequest, token_id: str = "") -> HttpResponse:
        """Handle unsubscribe link click via opaque token in URL path."""
        # Support both new path-based tokens and legacy query params
        if not token_id:
            token_id = request.GET.get("token", "")
        category = request.GET.get("category")

        if not token_id:
            return HttpResponse("Missing parameters", status=400)

        success = EmailPreferenceService.process_unsubscribe(token_id, category)

        if success:
            # Return a simple success page
            return HttpResponse(
                """
                <!DOCTYPE html>
                <html>
                <head><title>Unsubscribed</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>Successfully Unsubscribed</h1>
                    <p>You have been unsubscribed from marketing emails.</p>
                    <p>You will still receive important transactional emails about your account.</p>
                </body>
                </html>
                """,
                content_type="text/html",
            )
        else:
            return HttpResponse(
                """
                <!DOCTYPE html>
                <html>
                <head><title>Unsubscribe Failed</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>Unsubscribe Failed</h1>
                    <p>The unsubscribe link is invalid or has expired.</p>
                    <p>Please contact support if you need assistance.</p>
                </body>
                </html>
                """,
                content_type="text/html",
                status=400,
            )

    def post(self, request: HttpRequest, token_id: str = "") -> JsonResponse:
        """Handle unsubscribe API request."""
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        if not token_id:
            token_id = data.get("token", "")
        category = data.get("category")

        if not token_id:
            return JsonResponse({"error": "Missing parameters"}, status=400)

        success = EmailPreferenceService.process_unsubscribe(token_id, category)

        if success:
            return JsonResponse({"success": True, "message": "Successfully unsubscribed"})
        else:
            return JsonResponse({"success": False, "error": "Invalid or expired token"}, status=400)
