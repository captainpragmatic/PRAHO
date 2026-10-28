"""SES/SNS webhook hardening: topic allowlist, certificate host, signature versions, strict shape.

Every test except the allowlist tests configures the allowlist with the payload's TopicArn,
so each 403 comes from the check the test names. Rejections are asserted by response and by
side effect (no suppression row, no pending delivery event, no outbound fetch), never by
response code alone. Envelopes are signed by ``ses_sns_fixtures`` with its own canonical
builder, not the production one.
"""

from __future__ import annotations

import json
from typing import ClassVar
from unittest.mock import MagicMock, patch

import requests
from cryptography.hazmat.primitives import hashes
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError
from apps.notifications.models import EmailSuppression, PendingDeliveryEvent
from apps.notifications.services import EmailService
from apps.notifications.webhooks import SESWebhookView
from config.settings.test import LOCMEM_TEST_CACHE
from tests.notifications import ses_sns_fixtures as fx

LOGGER = "apps.notifications.webhooks"


def _dns_failure() -> OutboundSecurityError:
    """The error validate_and_resolve raises when the lookup itself fails (chained from the OSError)."""
    try:
        raise OutboundSecurityError("DNS resolution failed for 'sns.eu-west-1.amazonaws.com'") from OSError("lookup")
    except OutboundSecurityError as exc:
        return exc


@override_settings(DEBUG=False, SES_SNS_TOPIC_ARNS=(fx.TOPIC_ARN,))
class SESWebhookTestBase(TestCase):
    """Shared plumbing: a fake network, an audit spy, and rejection assertions."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.view = SESWebhookView.as_view()
        self.network = fx.FakeNetwork()
        real_handler = EmailService.handle_delivery_event
        for target, replacement in (
            ("apps.notifications.webhooks.safe_request", self.network),
            ("apps.notifications.webhooks.log_security_event", MagicMock()),
            # Wraps the real handler: an accepted message must write its real rows, so the "no row"
            # assertions on rejection can actually fail.
            ("apps.notifications.webhooks.EmailService.handle_delivery_event", MagicMock(wraps=real_handler)),
        ):
            patcher = patch(target, replacement)
            self.addCleanup(patcher.stop)
            mocked = patcher.start()
            if target.endswith("log_security_event"):
                self.audit = mocked
            elif target.endswith("handle_delivery_event"):
                self.delivery = mocked

    def post(self, payload: object, **extra: str) -> HttpResponse:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        request = self.factory.post("/webhooks/email/ses/", data=body, content_type="text/plain", **extra)
        return self.view(request)

    def assertRejected(self, response: HttpResponse, status: int, reason: str | None = None) -> None:  # noqa: N802
        self.assertEqual(response.status_code, status)
        self.delivery.assert_not_called()
        self.assertEqual(EmailSuppression.objects.count(), 0)
        self.assertEqual(PendingDeliveryEvent.objects.count(), 0)
        if reason is not None:
            self.audit.assert_called_once()
            self.assertEqual(self.audit.call_args.args[0], "email_webhook_invalid_signature")
            self.assertEqual(self.audit.call_args.args[1]["reason"], reason)

    def assertProcessed(self, response: HttpResponse, event_type: str = "bounced") -> None:  # noqa: N802
        self.assertEqual(response.status_code, 200)
        self.delivery.assert_called_once()
        self.assertEqual(self.delivery.call_args.kwargs["event_type"], event_type)
        self.assertEqual(self.delivery.call_args.kwargs["recipient"], "victim@example.com")
        # The real handler ran: the rows the rejection tests assert are absent really are written here.
        if event_type == "bounced":
            self.assertEqual(EmailSuppression.objects.count(), 1)
        else:
            self.assertTrue(PendingDeliveryEvent.objects.exists())


class SESCertificateHostTests(SESWebhookTestBase):
    """The signing certificate may only come from an SNS regional endpoint."""

    REJECTED_CERT_URLS: ClassVar[dict[str, str]] = {
        "s3 bucket": "https://s3.amazonaws.com/attacker-bucket/cert.pem",
        "other aws service": "https://ec2.eu-west-1.amazonaws.com/cert.pem",
        "explicit port": "https://sns.eu-west-1.amazonaws.com:443/cert.pem",
        "unparseable port": "https://sns.eu-west-1.amazonaws.com:port/cert.pem",
        "userinfo": "https://sns.eu-west-1.amazonaws.com@s3.amazonaws.com/cert.pem",
        "not a pem": "https://sns.eu-west-1.amazonaws.com/cert.txt",
        "china partition": "https://sns.cn-north-1.amazonaws.com.cn/cert.pem",
        "suffix trick": "https://sns.eu-west-1.amazonaws.com.evil.example/cert.pem",
    }

    def test_validly_signed_message_from_a_foreign_host_is_rejected_without_a_fetch(self) -> None:
        for label, cert_url in self.REJECTED_CERT_URLS.items():
            with self.subTest(label):
                self.network.calls.clear()
                self.audit.reset_mock()
                response = self.post(fx.sign(fx.envelope(), cert_url=cert_url))
                self.assertRejected(response, 403, "signing_cert_url_rejected")
                self.assertEqual(self.network.cert_fetches, [], f"{label}: the certificate must never be fetched")

    def test_regional_sns_host_is_accepted(self) -> None:
        for region in ("us-east-1", "eu-west-1", "ap-southeast-2"):
            with self.subTest(region):
                self.delivery.reset_mock()
                cert_url = f"https://sns.{region}.amazonaws.com/SimpleNotificationService-abc.pem"
                self.assertProcessed(self.post(fx.sign(fx.envelope(), cert_url=cert_url)))


class SESTopicAllowlistTests(SESWebhookTestBase):
    """The body TopicArn must be on the allowlist before any network call."""

    def test_topic_outside_the_allowlist_is_rejected_without_fetch_or_side_effect(self) -> None:
        response = self.post(fx.signed(TopicArn=fx.OTHER_TOPIC_ARN))
        self.assertRejected(response, 403, "topic_not_allowed")
        self.assertEqual(self.network.calls, [])

    def test_subscription_confirmation_from_a_foreign_topic_never_fetches_subscribe_url(self) -> None:
        response = self.post(fx.signed(fx.SUBSCRIPTION, TopicArn=fx.OTHER_TOPIC_ARN))
        self.assertRejected(response, 403, "topic_not_allowed")
        self.assertEqual(self.network.calls, [])

    def test_production_with_an_empty_allowlist_fails_closed_and_names_the_variable(self) -> None:
        with self.settings(SES_SNS_TOPIC_ARNS=()), self.assertLogs(LOGGER, level="ERROR") as logs:
            response = self.post(fx.signed())
        self.assertRejected(response, 403, "topic_allowlist_not_configured")
        self.assertEqual(self.network.calls, [])
        self.assertTrue(any("AWS_SES_SNS_TOPIC_ARNS" in line for line in logs.output), logs.output)

    def test_any_allowlisted_topic_is_accepted(self) -> None:
        with self.settings(SES_SNS_TOPIC_ARNS=(fx.OTHER_TOPIC_ARN, fx.TOPIC_ARN)):
            self.assertProcessed(self.post(fx.signed()))

    def test_authorized_arn_only_in_the_header_does_not_authorize_the_body(self) -> None:
        response = self.post(
            fx.signed(TopicArn=fx.OTHER_TOPIC_ARN),
            HTTP_X_AMZ_SNS_TOPIC_ARN=fx.TOPIC_ARN,
        )
        self.assertRejected(response, 403, "topic_not_allowed")

    def test_unauthorized_header_does_not_veto_an_authorized_body(self) -> None:
        response = self.post(fx.signed(), HTTP_X_AMZ_SNS_TOPIC_ARN=fx.OTHER_TOPIC_ARN)
        self.assertProcessed(response)

    def test_allowlisted_body_topic_with_signature_over_a_different_topic_is_rejected(self) -> None:
        forged = fx.sign(fx.envelope(), sign_over=fx.envelope(TopicArn=fx.OTHER_TOPIC_ARN))
        self.assertRejected(self.post(forged), 403)

    @override_settings(DEBUG=True, SES_SNS_TOPIC_ARNS=())
    def test_debug_with_an_empty_allowlist_accepts_an_unsigned_message(self) -> None:
        response = self.post(fx.envelope(Message=json.dumps(fx.ses_event("Delivery"))))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.delivery.call_args.kwargs["event_type"], "delivered")

    @override_settings(DEBUG=True, SES_SNS_TOPIC_ARNS=())
    def test_debug_with_an_empty_allowlist_warns_and_names_the_variable(self) -> None:
        with self.assertLogs(LOGGER, level="WARNING") as logs:
            self.post(fx.envelope(Message=json.dumps(fx.ses_event("Delivery"))))
        self.assertTrue(any("AWS_SES_SNS_TOPIC_ARNS" in line for line in logs.output), logs.output)

    @override_settings(DEBUG=True, SES_SNS_TOPIC_ARNS=(fx.TOPIC_ARN,))
    def test_debug_still_enforces_a_configured_allowlist(self) -> None:
        response = self.post(fx.envelope(TopicArn=fx.OTHER_TOPIC_ARN))
        self.assertRejected(response, 403, "topic_not_allowed")


class SESSignatureVersionTests(SESWebhookTestBase):
    def test_valid_v1_rsa_sha1_is_processed(self) -> None:
        self.assertProcessed(self.post(fx.signed()))

    def test_valid_v2_rsa_sha256_is_processed(self) -> None:
        self.assertProcessed(self.post(fx.sign(fx.envelope(), version="2")))

    def test_v2_declared_but_signed_with_sha1_is_rejected(self) -> None:
        forged = fx.sign(fx.envelope(), version="2", algorithm=hashes.SHA1())  # noqa: S303  # nosec B303  # nosemgrep: insecure-hash-algorithm-sha1
        self.assertRejected(self.post(forged), 403)

    def test_v1_declared_but_signed_with_sha256_is_rejected(self) -> None:
        forged = fx.sign(fx.envelope(), version="1", algorithm=hashes.SHA256())
        self.assertRejected(self.post(forged), 403)

    def test_unknown_signature_version_is_rejected_before_any_fetch(self) -> None:
        for version in ("0", "3", "SHA256", ""):
            with self.subTest(version):
                self.network.calls.clear()
                self.assertRejected(self.post({**fx.signed(), "SignatureVersion": version}), 403)
                self.assertEqual(self.network.cert_fetches, [])

    def test_missing_signature_is_rejected(self) -> None:
        payload = fx.signed()
        del payload["Signature"]
        self.assertRejected(self.post(payload), 403)

    def test_tampered_message_is_rejected(self) -> None:
        payload = fx.signed()
        payload["Message"] = json.dumps(fx.ses_event("Complaint"))
        self.assertRejected(self.post(payload), 403)

    def test_message_may_contain_newlines(self) -> None:
        pretty = json.dumps(fx.ses_event("Bounce"), indent=2)
        self.assertIn("\n", pretty)
        self.assertProcessed(self.post(fx.signed(Message=pretty)))

    def test_notification_without_subject_is_accepted(self) -> None:
        envelope = fx.envelope()
        del envelope["Subject"]
        self.assertProcessed(self.post(fx.sign(envelope)))

    def test_null_subject_is_treated_as_absent(self) -> None:
        # AWS's own validators skip a null Subject when building the signed string.
        envelope = fx.envelope()
        del envelope["Subject"]
        signed = fx.sign(envelope)
        signed["Subject"] = None
        self.assertProcessed(self.post(signed))


class SESCertificateFetchTests(SESWebhookTestBase):
    """Transient fetch failures are retryable (503); a bad certificate is permanent (403)."""

    def test_transient_fetch_failures_return_503_so_sns_retries(self) -> None:
        cases: dict[str, fx.FakeNetwork] = {
            "timeout": fx.FakeNetwork(cert_error=requests.exceptions.Timeout()),
            "connection error": fx.FakeNetwork(cert_error=requests.exceptions.ConnectionError()),
            "upstream 500": fx.FakeNetwork(cert_status=500),
            "upstream 502": fx.FakeNetwork(cert_status=502),
            "upstream 503": fx.FakeNetwork(cert_status=503),
            "rate limited": fx.FakeNetwork(cert_status=429),
            "dns lookup failed": fx.FakeNetwork(cert_error=_dns_failure()),
        }
        for label, network in cases.items():
            with self.subTest(label), patch("apps.notifications.webhooks.safe_request", network):
                self.assertRejected(self.post(fx.signed()), 503)

    def test_permanent_certificate_problems_return_403(self) -> None:
        cases: dict[str, fx.FakeNetwork] = {
            "not found": fx.FakeNetwork(cert_status=404),
            "forbidden": fx.FakeNetwork(cert_status=403),
            "garbage pem": fx.FakeNetwork(cert_body=b"-----BEGIN CERTIFICATE-----\nnope\n"),
            "blocked by outbound policy": fx.FakeNetwork(cert_error=OutboundSecurityError("blocked")),
        }
        for label, network in cases.items():
            with self.subTest(label), patch("apps.notifications.webhooks.safe_request", network):
                self.assertRejected(self.post(fx.signed()), 403)

    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_certificate_is_cached_between_requests(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.assertProcessed(self.post(fx.signed()))
        self.delivery.reset_mock()
        self.assertProcessed(self.post(fx.signed()))
        self.assertEqual(len(self.network.cert_fetches), 1)

    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_unusable_certificate_is_not_cached(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        with patch("apps.notifications.webhooks.safe_request", fx.FakeNetwork(cert_body=b"garbage")):
            self.assertRejected(self.post(fx.signed()), 403)
        self.assertProcessed(self.post(fx.signed()))


class SESSubscriptionTests(SESWebhookTestBase):
    """SubscriptionConfirmation is signed and allowlisted like everything else."""

    def test_valid_subscription_confirmation_is_confirmed_exactly_once_without_redirects(self) -> None:
        response = self.post(fx.signed(fx.SUBSCRIPTION))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.network.confirmation_fetches), 1)
        url, kwargs = self.network.confirmation_fetches[0]
        self.assertEqual(url, fx.SUBSCRIBE_URL)
        policy = kwargs["policy"]
        self.assertIsInstance(policy, OutboundPolicy)
        self.assertFalse(policy.allow_redirects)
        self.assertEqual(policy.max_redirects, 0)

    def test_valid_unsubscribe_confirmation_is_accepted_and_never_fetches_subscribe_url(self) -> None:
        response = self.post(fx.signed(fx.UNSUBSCRIPTION))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.network.confirmation_fetches, [])

    def test_subscribe_url_or_token_tampered_after_signing_is_rejected_without_a_get(self) -> None:
        for kind in (fx.SUBSCRIPTION, fx.UNSUBSCRIPTION):
            for field, value in (
                ("SubscribeURL", "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=forged"),
                ("Token", "forged-token"),
            ):
                with self.subTest(kind=kind, field=field):
                    self.network.calls.clear()
                    payload = fx.signed(kind)
                    payload[field] = value
                    self.assertRejected(self.post(payload), 403)
                    self.assertEqual(self.network.confirmation_fetches, [])

    def test_subscribe_url_on_a_non_sns_amazonaws_host_is_a_400_and_never_fetched(self) -> None:
        bad_urls = (
            "https://attacker-bucket.s3.amazonaws.com/confirm",
            "https://ec2.eu-west-1.amazonaws.com/?Action=ConfirmSubscription",
            "https://sns.eu-west-1.amazonaws.com.evil.example/confirm",
            "http://sns.eu-west-1.amazonaws.com/confirm",
            "https://user@s3.amazonaws.com/confirm",
        )
        for url in bad_urls:
            with self.subTest(url):
                self.network.calls.clear()
                with self.assertLogs(LOGGER, level="WARNING") as logs:
                    response = self.post(fx.signed(fx.SUBSCRIPTION, SubscribeURL=url))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.network.confirmation_fetches, [])
                self.assertTrue(any("SubscribeURL" in line for line in logs.output), logs.output)

    def test_confirmation_redirect_is_not_followed_and_is_not_reported_as_confirmed(self) -> None:
        network = fx.FakeNetwork(confirm_status=302)
        with patch("apps.notifications.webhooks.safe_request", network), self.assertLogs(LOGGER, level="INFO") as logs:
            response = self.post(fx.signed(fx.SUBSCRIPTION))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(network.confirmation_fetches), 1)
        self.assertFalse(any("confirmed" in line.lower() for line in logs.output), logs.output)

    def test_confirmation_failures_are_retryable(self) -> None:
        cases: dict[str, fx.FakeNetwork] = {
            "not found": fx.FakeNetwork(confirm_status=404),
            "upstream 500": fx.FakeNetwork(confirm_status=500),
            "transport error": fx.FakeNetwork(confirm_error=requests.exceptions.ConnectionError()),
        }
        for label, network in cases.items():
            with self.subTest(label), patch("apps.notifications.webhooks.safe_request", network):
                self.assertEqual(self.post(fx.signed(fx.SUBSCRIPTION)).status_code, 503)

    def test_outbound_policy_rejection_of_the_subscribe_url_stays_a_400(self) -> None:
        network = fx.FakeNetwork(confirm_error=OutboundSecurityError("blocked"))
        with patch("apps.notifications.webhooks.safe_request", network):
            self.assertEqual(self.post(fx.signed(fx.SUBSCRIPTION)).status_code, 400)


class SESStructuralValidationTests(SESWebhookTestBase):
    """Malformed bodies are a 400 before anything else runs, never a 500 and never a fetch."""

    def assertMalformed(self, response: HttpResponse) -> None:  # noqa: N802
        self.assertRejected(response, 400)
        self.assertEqual(self.network.calls, [])

    def test_bodies_that_are_not_json_objects_are_a_400(self) -> None:
        for raw in (b"[]", b'"text"', b"null", b"123", b"true", b"{not json", b"\xff\xfe\x00", b""):
            with self.subTest(raw=raw):
                self.assertMalformed(self.post(raw))

    def test_list_valued_topic_arn_is_a_400(self) -> None:
        self.assertMalformed(self.post(fx.signed(TopicArn=[fx.TOPIC_ARN])))

    def test_unknown_or_missing_type_is_a_400(self) -> None:
        self.assertMalformed(self.post(fx.signed(Type="SomethingElse")))
        payload = fx.signed()
        del payload["Type"]
        self.assertMalformed(self.post(payload))

    def test_missing_null_and_non_string_signed_fields_are_a_400(self) -> None:
        bad_values: dict[str, object] = {"null": None, "number": 123, "list": ["x"], "object": {"a": "b"}}
        for kind in fx.ALL_TYPES:
            for field in fx.REQUIRED_FIELDS[kind]:
                for label in ("missing", *bad_values):
                    with self.subTest(kind=kind, field=field, case=label):
                        envelope = fx.envelope(kind)
                        if label == "missing":
                            del envelope[field]
                        else:
                            envelope[field] = bad_values[label]
                        self.network.calls.clear()
                        self.assertMalformed(self.post(fx.sign(envelope)))

    def test_present_but_non_string_subject_is_a_400(self) -> None:
        for value in (7, ["s"]):
            with self.subTest(value=value):
                self.assertMalformed(self.post(fx.sign(fx.envelope(Subject=value))))

    def test_newlines_in_single_line_fields_are_a_400_even_when_validly_signed(self) -> None:
        single_line = {
            fx.NOTIFICATION: ("MessageId", "TopicArn", "Timestamp", "Subject"),
            fx.SUBSCRIPTION: ("MessageId", "TopicArn", "Timestamp", "SubscribeURL", "Token"),
            fx.UNSUBSCRIPTION: ("MessageId", "TopicArn", "Timestamp", "SubscribeURL", "Token"),
        }
        for kind, fields in single_line.items():
            for field in fields:
                for suffix in ("\nTopicArn\nattacker", "\r", "\n"):
                    with self.subTest(kind=kind, field=field, suffix=suffix):
                        envelope = fx.envelope(kind)
                        envelope[field] = f"{envelope[field]}{suffix}"
                        self.network.calls.clear()
                        self.assertMalformed(self.post(fx.sign(envelope)))

    def test_newlines_in_signature_header_fields_are_a_400(self) -> None:
        for field in ("SignatureVersion", "SigningCertURL"):
            with self.subTest(field):
                payload = fx.signed()
                payload[field] = f"{payload[field]}\n"
                self.assertMalformed(self.post(payload))

    def test_message_id_must_be_uuid_shaped(self) -> None:
        for message_id in ("test-123", "{12345678-1234-1234-1234-123456789012}", "12345678123412341234123456789012", ""):
            with self.subTest(message_id):
                self.assertMalformed(self.post(fx.signed(MessageId=message_id)))

    def test_timestamp_must_be_iso8601(self) -> None:
        for timestamp in ("yesterday", "2026-10-28", "2026-10-28 10:00:00", "1761645600"):
            with self.subTest(timestamp):
                self.assertMalformed(self.post(fx.signed(Timestamp=timestamp)))

    def test_canonical_reframing_across_the_message_boundary_is_a_400(self) -> None:
        # Message ends where a forged MessageId would begin; the signature is genuine for the
        # reframed string, so only the shape check can stop it.
        forged = fx.sign(fx.envelope(MessageId="00000000-0000-0000-0000-000000000000\nSubject\nx"))
        self.assertMalformed(self.post(forged))

    def test_non_string_signature_fields_are_rejected_not_crashed(self) -> None:
        for field in ("Signature", "SignatureVersion", "SigningCertURL"):
            for value in (None, 1, ["a"]):
                with self.subTest(field=field, value=value):
                    payload = fx.signed()
                    payload[field] = value
                    response = self.post(payload)
                    self.assertIn(response.status_code, (400, 403))
                    self.delivery.assert_not_called()


@override_settings(DEBUG=False, SES_SNS_TOPIC_ARNS=(fx.TOPIC_ARN,))
class SESRejectionAuditTrailTests(TestCase):
    """One unpatched test: the audit row carries the constant reason, not just the spy's call."""

    def test_rejection_writes_the_audit_event_with_its_reason(self) -> None:
        from apps.audit.models import AuditEvent  # noqa: PLC0415  # cross-app model, test-local

        network = fx.FakeNetwork()
        request = RequestFactory().post(
            "/webhooks/email/ses/",
            data=json.dumps(fx.signed(TopicArn=fx.OTHER_TOPIC_ARN)).encode(),
            content_type="text/plain",
            REMOTE_ADDR="203.0.113.7",
        )
        with patch("apps.notifications.webhooks.safe_request", network):
            response = SESWebhookView.as_view()(request)

        self.assertEqual(response.status_code, 403)
        event = AuditEvent.objects.get(action="email_webhook_invalid_signature")
        self.assertEqual(event.metadata["reason"], "topic_not_allowed")
        self.assertEqual(event.metadata["provider"], "ses")
        self.assertEqual(network.calls, [])
