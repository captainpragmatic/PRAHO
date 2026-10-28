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
import re
import time
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

import requests
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_pem_x509_certificate
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request
from apps.common.validators import log_security_event
from apps.notifications.services import EmailPreferenceService, EmailService

_HTTP_OK = 200
_HTTP_MULTIPLE_CHOICES = 300
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR = 500

# The confirmation GET must reach the host that was validated: a redirect is not followed.
SNS_CONFIRMATION_POLICY = OutboundPolicy(
    name="sns_confirmation",
    allowed_domains=frozenset({"amazonaws.com"}),
    allow_redirects=False,
    max_redirects=0,
    timeout_seconds=10.0,
)

# SNS signs these fields, in this order, per message type (the optional Subject only when present).
_SNS_NOTIFICATION = "Notification"
_SNS_SUBSCRIPTION = "SubscriptionConfirmation"
_SNS_UNSUBSCRIPTION = "UnsubscribeConfirmation"
_SNS_NOTIFICATION_FIELDS = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
_SNS_CONFIRMATION_FIELDS = ("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type")
_SNS_SIGNED_FIELDS: dict[str, tuple[str, ...]] = {
    _SNS_NOTIFICATION: _SNS_NOTIFICATION_FIELDS,
    _SNS_SUBSCRIPTION: _SNS_CONFIRMATION_FIELDS,
    _SNS_UNSUBSCRIPTION: _SNS_CONFIRMATION_FIELDS,
}
_SNS_OPTIONAL_FIELDS = frozenset({"Subject"})
# A newline in any of these would let one field be reframed as another inside the signed string.
_SNS_SINGLE_LINE_FIELDS = frozenset(
    {
        "MessageId",
        "TopicArn",
        "Type",
        "Timestamp",
        "SubscribeURL",
        "Token",
        "Subject",
        "SignatureVersion",
        "SigningCertURL",
    }
)
_SNS_SIGNATURE_FIELDS = ("SignatureVersion", "SigningCertURL", "Signature")

# China (.com.cn) and FIPS endpoints are not supported: SNS emits regional sns.<region>.amazonaws.com hosts.
_SNS_HOST_PATTERN = re.compile(r"sns\.[a-z0-9-]+\.amazonaws\.com")
_UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")

_SNS_CERT_CACHE_PREFIX = "ses_sns_signing_cert:"
_SNS_CERT_CACHE_SECONDS = 3600
_SNS_CERT_TIMEOUT_SECONDS = 10

logger = logging.getLogger(__name__)


class _SNSRejectionError(Exception):
    """An SNS message that must not be processed.

    ``reason`` is a constant (never request data): it goes to the audit trail for 403s.
    400 means malformed, 403 means not authentic or not authorized, 503 means SNS should retry.
    """

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _is_sns_url(url: str, *, pem: bool = False) -> bool:
    """True for an https URL on a regional SNS host: no userinfo, no explicit port (and a .pem path if ``pem``)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and "@" not in parsed.netloc
        and port is None
        and parsed.hostname is not None
        and _SNS_HOST_PATTERN.fullmatch(parsed.hostname) is not None
        and (not pem or parsed.path.endswith(".pem"))
    )


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
            try:
                fields = self._parse_envelope(request.body)
                self._authorize_topic(fields)
                self._verify_signature(fields)
            except _SNSRejectionError as rejection:
                return self._reject(request, rejection)

            message_type = fields["Type"]

            # Handle SNS subscription confirmation
            if message_type == _SNS_SUBSCRIPTION:
                return self._handle_subscription_confirmation(fields)

            # Handle notification
            if message_type == _SNS_NOTIFICATION:
                return self._handle_notification(fields)

            return HttpResponse("OK", status=200)

        except Exception as e:
            logger.exception(f"SES webhook error: {e}")
            return HttpResponse("Error", status=500)

    def _reject(self, request: HttpRequest, rejection: _SNSRejectionError) -> HttpResponse:
        """Turn a rejection into its response. Only authentication failures reach the audit trail."""
        if rejection.status == HTTPStatus.FORBIDDEN:
            log_security_event(
                "email_webhook_invalid_signature",
                {"provider": "ses", "remote_addr": request.META.get("REMOTE_ADDR"), "reason": rejection.reason},
            )
            return HttpResponse("Forbidden", status=403)
        if rejection.status == HTTPStatus.SERVICE_UNAVAILABLE:
            logger.warning("⚠️ [SES] Signing certificate unavailable, asking SNS to retry (%s)", rejection.reason)
            return HttpResponse("Temporarily unavailable", status=503)
        logger.warning("⚠️ [SES] Malformed SNS message rejected (%s)", rejection.reason)
        return HttpResponse("Malformed SNS message", status=400)

    def _parse_envelope(self, body: bytes) -> dict[str, str]:
        """Parse and shape-check the SNS envelope before anything is trusted or fetched.

        Returns only the string fields the rest of the view uses. The shape rules close the
        reframing ambiguity of the signed string (newlines in single-line fields) and remove
        the 500s on non-object bodies and non-string values.
        """
        try:
            parsed = json.loads(body)
        except ValueError:  # JSONDecodeError and UnicodeDecodeError
            raise _SNSRejectionError(400, "invalid_json") from None
        if not isinstance(parsed, dict):
            raise _SNSRejectionError(400, "not_an_object")

        message_type = parsed.get("Type")
        if not isinstance(message_type, str) or message_type not in _SNS_SIGNED_FIELDS:
            raise _SNSRejectionError(400, "unknown_type")

        fields: dict[str, str] = {}
        for name in _SNS_SIGNED_FIELDS[message_type]:
            # AWS's own validators treat a null optional field (Subject) as absent from the signed string.
            if name not in parsed or (parsed[name] is None and name in _SNS_OPTIONAL_FIELDS):
                if name in _SNS_OPTIONAL_FIELDS:
                    continue
                raise _SNSRejectionError(400, "missing_field")
            fields[name] = self._string_field(parsed[name])
        # The signature header fields are optional here: the DEBUG unsigned bypass has none.
        for name in _SNS_SIGNATURE_FIELDS:
            if name in parsed:
                fields[name] = self._string_field(parsed[name])

        if any(("\n" in value or "\r" in value) for name, value in fields.items() if name in _SNS_SINGLE_LINE_FIELDS):
            raise _SNSRejectionError(400, "multiline_field")
        if not _UUID_PATTERN.fullmatch(fields["MessageId"]):
            raise _SNSRejectionError(400, "bad_message_id")
        if not _TIMESTAMP_PATTERN.fullmatch(fields["Timestamp"]):
            raise _SNSRejectionError(400, "bad_timestamp")
        return fields

    @staticmethod
    def _string_field(value: object) -> str:
        if not isinstance(value, str):
            raise _SNSRejectionError(400, "non_string_field")
        return value

    def _authorize_topic(self, fields: dict[str, str]) -> None:
        """Only messages from an explicitly allowlisted topic are considered, before any network call.

        The ARN comes from the signed body; the x-amz-sns-topic-arn header is never consulted.
        """
        allowed = tuple(getattr(settings, "SES_SNS_TOPIC_ARNS", ()))
        if not allowed:
            if getattr(settings, "DEBUG", False):
                logger.warning("⚠️ [SES] AWS_SES_SNS_TOPIC_ARNS is empty: accepting any TopicArn (DEBUG mode)")
                return
            logger.error("🔥 [SES] AWS_SES_SNS_TOPIC_ARNS is not configured: rejecting every SNS message")
            raise _SNSRejectionError(403, "topic_allowlist_not_configured")
        if fields["TopicArn"] not in allowed:
            logger.warning("⚠️ [SES] TopicArn is not on the AWS_SES_SNS_TOPIC_ARNS allowlist")
            raise _SNSRejectionError(403, "topic_not_allowed")

    def _verify_signature(self, fields: dict[str, str]) -> None:
        """Validate the AWS SNS message signature, raising _SNSRejectionError unless it is genuine.

        In DEBUG mode, accepts unsigned messages for dev convenience, matching the
        pattern used by the SendGrid and Mailgun handlers.

        See: https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
        """
        if getattr(settings, "DEBUG", False) and not fields.get("Signature"):
            logger.warning("SES webhook: accepting unsigned SNS message (DEBUG mode)")
            return

        version = fields.get("SignatureVersion")
        if version == "1":
            # AWS SNS SignatureVersion 1 mandates RSA-SHA1.
            algorithm: hashes.HashAlgorithm = hashes.SHA1()  # noqa: S303  # nosec B303  # nosemgrep: insecure-hash-algorithm-sha1
        elif version == "2":
            algorithm = hashes.SHA256()
        else:
            logger.warning("SES webhook: unsupported SignatureVersion")
            raise _SNSRejectionError(403, "signature_version_unsupported")

        signing_cert_url = fields.get("SigningCertURL", "")
        if not _is_sns_url(signing_cert_url, pem=True):
            logger.warning("SES webhook: invalid SigningCertURL")
            raise _SNSRejectionError(403, "signing_cert_url_rejected")

        if not fields.get("Signature"):
            logger.warning("SES webhook: empty signature")
            raise _SNSRejectionError(403, "signature_missing")

        public_key = self._signing_public_key(signing_cert_url)
        try:
            public_key.verify(
                base64.b64decode(fields["Signature"], validate=True),
                self._canonical_message(fields).encode("utf-8"),
                padding.PKCS1v15(),
                algorithm,
            )
        except (ValueError, InvalidSignature, UnsupportedAlgorithm):
            logger.warning("SES webhook: signature verification failed")
            raise _SNSRejectionError(403, "signature_mismatch") from None

    def _canonical_message(self, fields: dict[str, str]) -> str:
        """Build the canonical string to verify per the AWS SNS signing specification."""
        order = _SNS_SIGNED_FIELDS[fields["Type"]]
        return "".join(f"{name}\n{fields[name]}\n" for name in order if name in fields)

    def _signing_public_key(self, url: str) -> rsa.RSAPublicKey:
        """Return the RSA key of the SNS signing certificate, fetched once per hour per URL."""
        cache_key = _SNS_CERT_CACHE_PREFIX + hashlib.sha256(url.encode()).hexdigest()
        cached = cache.get(cache_key)
        pem = cached if isinstance(cached, bytes) else self._download_signing_cert(url)
        try:
            public_key = load_pem_x509_certificate(pem).public_key()
        except ValueError:
            logger.warning("SES webhook: signing certificate is not a valid PEM certificate")
            raise _SNSRejectionError(403, "signing_cert_unusable") from None
        if not isinstance(public_key, rsa.RSAPublicKey):
            logger.warning("SES webhook: unexpected public key type %s", type(public_key).__name__)
            raise _SNSRejectionError(403, "signing_cert_unusable")
        if not isinstance(cached, bytes):
            cache.set(cache_key, pem, _SNS_CERT_CACHE_SECONDS)
        return public_key

    def _download_signing_cert(self, url: str) -> bytes:
        """Fetch the signing certificate. Transient failures are 503 so SNS retries the delivery."""
        try:
            response = safe_request("GET", url, timeout=_SNS_CERT_TIMEOUT_SECONDS)
        except OutboundSecurityError as exc:
            # The host is already pinned to SNS, so a failed DNS lookup (chained from the OSError) is transient.
            if isinstance(exc.__cause__, OSError):
                raise _SNSRejectionError(503, "signing_cert_unavailable") from None
            logger.warning("SES webhook: signing certificate fetch blocked by the outbound policy")
            raise _SNSRejectionError(403, "signing_cert_unusable") from None
        except requests.RequestException:
            raise _SNSRejectionError(503, "signing_cert_unavailable") from None
        if response.status_code >= _HTTP_SERVER_ERROR or response.status_code == _HTTP_TOO_MANY_REQUESTS:
            raise _SNSRejectionError(503, "signing_cert_unavailable")
        if response.status_code != _HTTP_OK:
            logger.warning("SES webhook: failed to fetch signing certificate (HTTP %s)", response.status_code)
            raise _SNSRejectionError(403, "signing_cert_unusable")
        return bytes(response.content)

    def _handle_subscription_confirmation(self, data: dict[str, str]) -> HttpResponse:
        """Handle SNS subscription confirmation."""
        subscribe_url = data.get("SubscribeURL")
        if subscribe_url:
            # Only a regional SNS host is contacted; the policy adds SSRF validation and forbids redirects.
            if not _is_sns_url(subscribe_url):
                logger.warning("⚠️ [SNS] Rejected SubscribeURL: not a regional SNS https URL")
                return HttpResponse("Invalid SubscribeURL", status=400)
            try:
                response = safe_request("GET", subscribe_url, policy=SNS_CONFIRMATION_POLICY)
            except OutboundSecurityError as e:
                logger.warning(f"⚠️ [SNS] Rejected SubscribeURL: {e}")
                return HttpResponse("Invalid SubscribeURL", status=400)
            except requests.RequestException as e:
                logger.error(f"🔥 [SNS] Failed to confirm subscription: {e}")
                return HttpResponse("Confirmation failed", status=503)
            if not _HTTP_OK <= response.status_code < _HTTP_MULTIPLE_CHOICES:
                logger.error(f"🔥 [SNS] Subscription confirmation answered HTTP {response.status_code}")
                return HttpResponse("Confirmation failed", status=503)
            logger.info("✅ [SNS] Subscription confirmed")

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


def _sendgrid_signature_valid(public_key_b64: str, signature_b64: str, signed: bytes) -> bool:
    """SendGrid signs timestamp + raw body with ECDSA P-256 / SHA-256.

    The verification key SendGrid publishes is that public key (base64 DER), so a keyed hash over it,
    as this check once was, proves nothing: anyone holding the key could produce it.
    """
    try:
        public_key = serialization.load_der_public_key(base64.b64decode(public_key_b64))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.error("SendGrid webhook key is not an elliptic-curve public key - rejecting")
            return False
        public_key.verify(base64.b64decode(signature_b64), signed, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, binascii.Error):
        return False
    return True


# How old a signed SendGrid delivery may be (seconds); SendGrid retries with a fresh timestamp.
SENDGRID_SIGNATURE_MAX_AGE_SECONDS = 300
# The same for Mailgun, whose signed tokens are also refused a second time within twice this.
MAILGUN_SIGNATURE_MAX_AGE_SECONDS = 300


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

        if not signature or not timestamp or not timestamp.isdigit():
            return False
        if abs(time.time() - int(timestamp)) > SENDGRID_SIGNATURE_MAX_AGE_SECONDS:
            return False  # a captured delivery cannot be replayed later
        return _sendgrid_signature_valid(webhook_key, signature, timestamp.encode() + request.body)

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
        if not hmac.compare_digest(signature, expected):
            return False
        # The signature covers only timestamp and token, not the event: a captured triple must be
        # fresh and used once, or it could carry any event body again.
        try:
            fresh = abs(time.time() - int(timestamp)) <= MAILGUN_SIGNATURE_MAX_AGE_SECONDS
        except ValueError:
            return False
        return fresh and cache.add(f"mailgun-webhook-token:{token}", 1, MAILGUN_SIGNATURE_MAX_AGE_SECONDS * 2)

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
