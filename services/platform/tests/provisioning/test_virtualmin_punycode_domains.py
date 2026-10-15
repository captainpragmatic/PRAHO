"""Punycode (IDNA A-label) domains must pass every Virtualmin validation layer.

An internationalized domain is stored and sent as its ASCII A-label (``xn--bcher-kva.ro``).
The injection heuristics read the ``--`` of that prefix as an SQL comment, so such a
domain was refused at three places: the shared suspicious-pattern check, the
Virtualmin call-time parameter check, and the provisioning-time domain validator.
A value that starts with ``-`` (option injection) and an invalid A-label stay refused.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings

from apps.common.validators import SecureInputValidator
from apps.provisioning.security_utils import ProvisioningParametersValidator
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_validators import VirtualminValidator
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

PUNYCODE_DOMAIN = "xn--bcher-kva.ro"
PUNYCODE_TLD_DOMAIN = "example.xn--p1ai"
OPTION_INJECTIONS = ("--option", "-x", "--pass=secret", "-")
INVALID_A_LABELS = ("xn--.ro", "xn--a.ro", "xn--zzzz-.ro", "xn--bcher-kva-.ro")


class SharedPatternCheckTests(SimpleTestCase):
    """Layer 1: apps.common.validators.SUSPICIOUS_PATTERNS."""

    def test_a_label_prefix_is_not_an_sql_comment(self) -> None:
        for value in (PUNYCODE_DOMAIN, PUNYCODE_TLD_DOMAIN, "www.xn--bcher-kva.ro", "XN--BCHER-KVA.RO"):
            with self.subTest(value=value):
                SecureInputValidator._check_malicious_patterns(value)

    def test_real_double_hyphens_are_still_refused(self) -> None:
        for value in (
            "--option",
            "a -- b",
            "foo--bar.ro",
            "bad.xxn--foo.ro",
            "1 or 1=1 xn--",
            "xn-- drop",
            "x'; --",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                SecureInputValidator._check_malicious_patterns(value)


class DomainNameValidatorTests(SimpleTestCase):
    """Layer 2a: VirtualminValidator.validate_domain_name."""

    def test_a_label_domains_are_accepted(self) -> None:
        for domain in (PUNYCODE_DOMAIN, PUNYCODE_TLD_DOMAIN, "www.XN--BCHER-KVA.RO"):
            with self.subTest(domain=domain):
                self.assertEqual(VirtualminValidator.validate_domain_name(domain), domain.lower())

    def test_option_injection_and_invalid_idna_are_refused(self) -> None:
        for domain in (*OPTION_INJECTIONS, *INVALID_A_LABELS, "ab--cd.ro"):
            with self.subTest(domain=domain), self.assertRaises(ValidationError):
                VirtualminValidator.validate_domain_name(domain)


class CallTimeParameterTests(SimpleTestCase):
    """Layer 2b: VirtualminValidator.validate_virtualmin_params, run by every gateway call."""

    def test_a_label_domain_parameter_is_accepted(self) -> None:
        for key in ("domain", "parent"):
            with self.subTest(key=key):
                params = VirtualminValidator.validate_virtualmin_params({key: PUNYCODE_DOMAIN, "user": "bucher"})
                self.assertEqual(params[key], PUNYCODE_DOMAIN)

    def test_option_injection_in_a_domain_parameter_is_refused(self) -> None:
        for key in ("domain", "parent"):
            for value in OPTION_INJECTIONS:
                with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                    VirtualminValidator.validate_virtualmin_params({key: value})

    def test_invalid_a_label_in_a_domain_parameter_is_refused(self) -> None:
        for value in INVALID_A_LABELS:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VirtualminValidator.validate_virtualmin_params({"domain": value})

    def test_other_values_keep_the_strict_check(self) -> None:
        for value in ("a -- b", "x'; --"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VirtualminValidator.validate_virtualmin_params({"desc": value})

    def test_non_domain_values_may_still_start_with_a_hyphen(self) -> None:
        # Generated passwords draw from a set that includes "-"; only domain keys are option-shaped.
        params = VirtualminValidator.validate_virtualmin_params({"pass": "-aB3!xyz-Q9", "quota": "-1"})
        self.assertEqual(params["pass"], "-aB3!xyz-Q9")


class ProvisioningDomainValidatorTests(SimpleTestCase):
    """Layer 3: ProvisioningParametersValidator.validate_domain, the first gate of a create."""

    def test_a_label_domains_are_accepted(self) -> None:
        for domain in (PUNYCODE_DOMAIN, PUNYCODE_TLD_DOMAIN, "  WWW.XN--BCHER-KVA.RO "):
            with self.subTest(domain=domain):
                self.assertEqual(ProvisioningParametersValidator.validate_domain(domain), domain.strip().lower())

    def test_option_injection_and_invalid_idna_are_refused(self) -> None:
        for domain in ("--option.ro", "-x.ro", *INVALID_A_LABELS, "ab--cd.ro"):
            with self.subTest(domain=domain), self.assertRaises(ValidationError):
                ProvisioningParametersValidator.validate_domain(domain)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class GatewayCallTests(VirtualminTaskTestBase):
    """The gateway sends a punycode domain to the node and refuses an option-shaped one before sending."""

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server))

    def test_gateway_call_sends_the_a_label(self) -> None:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(cast("dict[str, object]", kwargs["params"]))
            return http_response({"status": "success", "data": []})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.gateway.call("list-domains", {"domain": PUNYCODE_DOMAIN})

        self.assertTrue(result.is_ok(), result)
        self.assertEqual([p["domain"] for p in sent], [PUNYCODE_DOMAIN])

    def test_gateway_call_refuses_option_injection_without_a_request(self) -> None:
        for value in ("--option", "-x"):
            with (
                self.subTest(value=value),
                patch("apps.provisioning.virtualmin_gateway.safe_request") as transport,
            ):
                result = self.gateway.call("list-domains", {"domain": value})
            self.assertTrue(result.is_err())
            transport.assert_not_called()
