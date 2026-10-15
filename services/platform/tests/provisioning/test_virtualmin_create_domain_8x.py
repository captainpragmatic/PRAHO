"""create-domain must be valid on Virtualmin 8.x, and an absent domain must read as absent.

Observed against Virtualmin 8.3.0 in deploy/virtualmin-lab:
- the built-in template is "Default Settings"; `--template Default` fails with
  "Unknown template name";
- without a feature flag create-domain fails with "No virtual server features
  enabled";
- `list-domains --domain <absent>` answers with the failure envelope below,
  which made every single-domain probe an error instead of "absent".
"""

from __future__ import annotations

import json
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings

from apps.common.types import Ok
from apps.provisioning.models import Service
from apps.provisioning.security_utils import ProvisioningParametersValidator
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.provisioning.virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE, VirtualminValidator
from tests.helpers.recorded_virtualmin import (
    RECORDED_ABSENT_DOMAIN,
    recorded_http_response,
    recorded_payload,
)
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_backup_cli_contract import remote_cgi_argv
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


def absent_envelope(domain: str) -> dict[str, object]:
    """Virtualmin 8.3.0's recorded answer to list-domains for an absent domain, for `domain`."""
    envelope: dict[str, object] = recorded_payload(
        "list-domains", "absent_domain", replace={RECORDED_ABSENT_DOMAIN: domain}
    )
    return envelope


class TemplateNameTests(SimpleTestCase):
    def test_default_is_virtualmins_real_template_name(self) -> None:
        self.assertEqual(DEFAULT_VIRTUALMIN_TEMPLATE, "Default Settings")
        self.assertEqual(VirtualminValidator.validate_template_name(""), "Default Settings")
        self.assertEqual(ProvisioningParametersValidator.validate_template(""), "Default Settings")
        self.assertEqual(VirtualminAccount._meta.get_field("template_name").default, "Default Settings")
        self.assertEqual(VirtualminAccountCreationData(service=None, domain="a.test").template, "Default Settings")

    def test_validator_accepts_single_spaces_only(self) -> None:
        for name in ("Default Settings", "Settings For Sub-Servers", "plan_a-1"):
            with self.subTest(name=name):
                self.assertEqual(VirtualminValidator.validate_template_name(name), name)
        for name in ("Default  Settings", " Default", "Default ", "a\tb", "x" * 51):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                VirtualminValidator.validate_template_name(name)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class AbsentDomainProbeTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server))

    def _answer(self, payload: dict[str, object]) -> object:
        return patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(payload))

    def test_virtualmins_absent_answer_reads_as_absent(self) -> None:
        with self._answer(absent_envelope("gone.example.com")):
            self.assertEqual(
                self.gateway.get_domain_state("gone.example.com").unwrap(),
                {"exists": False, "enabled": None, "owner": ""},
            )
        with self._answer(absent_envelope("gone.example.com")):
            self.assertEqual(self.gateway.get_domain_owner("gone.example.com"), Ok(None))

    def test_any_other_failure_stays_an_error(self) -> None:
        for payload in (
            absent_envelope("other.example.com"),
            {"status": "failure", "error": "Virtual server gone.example.com does not exist yet"},
            {"status": "failure", "error": "Permission denied"},
            {"status": "failure"},
        ):
            with self.subTest(payload=payload):
                with self._answer(payload):
                    self.assertTrue(self.gateway.get_domain_state("gone.example.com").is_err())
                with self._answer(payload):
                    self.assertTrue(self.gateway.get_domain_owner("gone.example.com").is_err())

    def test_create_retry_recreates_an_absent_domain(self) -> None:
        job = self._failed_job()
        service = VirtualminProvisioningService(self.server)
        with (
            self._answer(absent_envelope(self.account.domain)),
            patch.object(service, "_execute_domain_creation", return_value=Ok({})) as create,
        ):
            result = service._retry_create_domain(self.account, job)
        self.assertTrue(result.is_ok(), result)
        create.assert_called_once()


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class CreateDomainParameterTests(VirtualminTaskTestBase):
    def test_create_domain_sends_the_real_template_and_default_features(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            sent.append(params)
            return recorded_http_response(str(params["program"]))

        account = VirtualminAccount.objects.create(
            domain="new.example.com",
            service=Service.objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.currency,
                service_name="new.example.com",
                domain="new.example.com",
                username="newexample",
                billing_cycle="monthly",
                price=self.service.price,
                status="active",
            ),
            server=self.server,
            virtualmin_username="newexample",
            status="provisioning",
        )
        account.set_password("Account-Password-1")
        account.save()
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain", server=self.server, account=account, correlation_id="c"
        )
        service = VirtualminProvisioningService(self.server)
        with (
            patch.object(service, "_validate_provisioning_preconditions", return_value=Ok(True)),
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport),
        ):
            result = service._execute_domain_creation(account, job)
        self.assertTrue(result.is_ok(), result)
        create = [params for params in sent if params.get("program") == "create-domain"]
        self.assertEqual(len(create), 1)
        argv = remote_cgi_argv(create[0])
        self.assertEqual(argv[argv.index("--template") + 1], "Default Settings")
        self.assertIn("--default-features", argv)
        # A bare flag: nothing may follow it as a value.
        following = argv[argv.index("--default-features") + 1 :]
        self.assertTrue(not following or following[0].startswith("--"), json.dumps(argv))
