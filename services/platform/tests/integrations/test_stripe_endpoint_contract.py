"""The webhook rendering version and standalone Refund payloads are explicit."""

import hashlib
import hmac
import json
import secrets
import time
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from apps.common.types import Ok
from apps.integrations.webhooks.stripe import StripeWebhookProcessor

REQUIRED_EVENTS = {
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
    "customer.created",
    "charge.dispute.created",
    "refund.created",
    "refund.updated",
    "refund.failed",
}


class StripeEndpointContractTests(TestCase):
    def _inspect(self, **overrides):
        endpoint = {
            "id": "we_contract",
            "api_version": "2023-10-16",
            "enabled_events": sorted(REQUIRED_EVENTS),
            "status": "enabled",
            **overrides,
        }
        with (
            patch("apps.settings.services.SettingsService.get_setting", return_value=secrets.token_hex(32)),
            patch("stripe.WebhookEndpoint.retrieve", return_value=endpoint) as retrieve,
        ):
            call_command("inspect_stripe_webhook", "we_contract", stdout=StringIO())
            retrieve.assert_called_once_with("we_contract")

    def test_endpoint_with_pinned_version_and_required_events_passes(self) -> None:
        self._inspect()

    def test_missing_refund_subscriptions_fail_inspection(self) -> None:
        with self.assertRaisesMessage(CommandError, "refund.created"):
            self._inspect(enabled_events=["payment_intent.succeeded"])

    def test_version_mismatch_requires_replacement_instead_of_update(self) -> None:
        with self.assertRaisesMessage(CommandError, "replacement"):
            self._inspect(api_version="2022-11-15")

    def test_signed_standalone_refund_payloads_are_accepted(self) -> None:
        secret = secrets.token_hex(32)
        for kind, status in (("created", "succeeded"), ("updated", "succeeded"), ("failed", "failed")):
            payload = {
                "id": f"evt_refund_{kind}",
                "type": f"refund.{kind}",
                "data": {
                    "object": {
                        "id": "re_contract",
                        "payment_intent": "pi_contract",
                        "amount": 100,
                        "currency": "ron",
                        "status": status,
                    }
                },
            }
            body = json.dumps(payload).encode()
            timestamp = str(int(time.time()))
            digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
            with (
                self.subTest(kind=kind),
                override_settings(STRIPE_WEBHOOK_SECRET=secret),
                patch("apps.settings.services.SettingsService.get_setting", return_value=None),
                patch(
                    "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
                    return_value=Ok(SimpleNamespace(gateway_refund_id="re_contract", status=status)),
                ) as converge,
            ):
                accepted, message, event = StripeWebhookProcessor().process_webhook(
                    payload,
                    signature=f"t={timestamp},v1={digest}",
                    raw_body=body,
                )
                self.assertTrue(accepted, message)
                self.assertEqual(event.status, "processed")
                self.assertEqual(converge.call_args.args[0]["refund_id"], "re_contract")
