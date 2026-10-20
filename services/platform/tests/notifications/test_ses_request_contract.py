"""Exercise the installed SES adapter, substituting only its AWS client."""

import os
import runpy
from importlib import import_module
from unittest.mock import patch

from django.core.mail import EmailMessage
from django.test import TestCase, override_settings


class SESRequestContractTests(TestCase):
    def test_supported_production_backends_are_importable(self) -> None:
        for provider in ("amazon_ses", "sendgrid", "mailgun"):
            with self.subTest(provider=provider):
                self.assertTrue(callable(import_module(f"anymail.backends.{provider}").EmailBackend))

    def test_real_ses_request_uses_operator_configuration_set(self) -> None:
        with patch.dict(os.environ, {"AWS_SES_CONFIGURATION_SET": "praho-events"}):
            anymail = runpy.run_module("config.settings.base", run_name="config.settings._ses_contract")["ANYMAIL"]
        with (
            override_settings(EMAIL_BACKEND="anymail.backends.amazon_ses.EmailBackend", ANYMAIL=anymail),
            patch("boto3.session.Session.client") as client_factory,
        ):
            client = client_factory.return_value
            client.send_email.return_value = {"MessageId": "ses-contract-message"}
            self.assertEqual(EmailMessage("Contract", "Body", "sender@example.com", ["to@example.com"]).send(), 1)
        request = client.send_email.call_args.kwargs
        self.assertEqual(request["ConfigurationSetName"], "praho-events")
        self.assertEqual(request["Destination"]["ToAddresses"], ["to@example.com"])
        self.assertIn(b"Body", request["Content"]["Raw"]["Data"])
