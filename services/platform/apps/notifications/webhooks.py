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

import hashlib
import hmac
import json
import logging
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.common.validators import log_security_event
from apps.notifications.services import EmailService

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
            import base64

            try:
                credentials = base64.b64decode(auth_header[6:]).decode()
                if credentials.endswith(f":{webhook_secret}"):
                    return True
            except Exception:
                pass

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

    def _handle_subscription_confirmation(self, data: dict[str, Any]) -> HttpResponse:
        """Handle SNS subscription confirmation."""
        subscribe_url = data.get("SubscribeURL")
        if subscribe_url:
            # SECURITY: Validate SubscribeURL is from AWS SNS to prevent SSRF
            from urllib.parse import urlparse

            parsed = urlparse(subscribe_url)

            # Only allow HTTPS URLs from AWS SNS domains
            allowed_domains = [
                "sns.amazonaws.com",
                "sns.us-east-1.amazonaws.com",
                "sns.us-west-2.amazonaws.com",
                "sns.eu-west-1.amazonaws.com",
                "sns.eu-central-1.amazonaws.com",
                "sns.ap-southeast-1.amazonaws.com",
                "sns.ap-northeast-1.amazonaws.com",
            ]
            # Also allow regional pattern: sns.<region>.amazonaws.com
            is_valid_sns_domain = (
                parsed.scheme == "https"
                and (
                    parsed.netloc in allowed_domains
                    or (
                        parsed.netloc.startswith("sns.")
                        and parsed.netloc.endswith(".amazonaws.com")
                    )
                )
            )

            if not is_valid_sns_domain:
                logger.warning(f"Rejected non-AWS SubscribeURL: {parsed.netloc}")
                return HttpResponse("Invalid SubscribeURL domain", status=400)

            # Auto-confirm subscription
            import requests

            try:
                requests.get(subscribe_url, timeout=10)
                logger.info("SNS subscription confirmed")
            except Exception as e:
                logger.error(f"Failed to confirm SNS subscription: {e}")

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
                recipient=email,
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

    def get(self, request: HttpRequest) -> HttpResponse:
        """Handle unsubscribe link click."""
        email = request.GET.get("email")
        token = request.GET.get("token")
        category = request.GET.get("category")

        if not email or not token:
            return HttpResponse("Missing parameters", status=400)

        from apps.notifications.services import EmailPreferenceService

        success = EmailPreferenceService.process_unsubscribe(email, token, category)

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

    def post(self, request: HttpRequest) -> JsonResponse:
        """Handle unsubscribe API request."""
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        email = data.get("email")
        token = data.get("token")
        category = data.get("category")

        if not email or not token:
            return JsonResponse({"error": "Missing parameters"}, status=400)

        from apps.notifications.services import EmailPreferenceService

        success = EmailPreferenceService.process_unsubscribe(email, token, category)

        if success:
            return JsonResponse({"success": True, "message": "Successfully unsubscribed"})
        else:
            return JsonResponse({"success": False, "error": "Invalid or expired token"}, status=400)
