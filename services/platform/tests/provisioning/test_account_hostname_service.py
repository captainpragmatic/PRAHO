"""The account-name service (ADR-0061 P1.4).

The node side runs against a fake node that answers like Virtualmin 8.3 (lab-recorded shapes:
`type`, `parent_domain`, the owner, "You are already hosting this domain"). The DNS side runs
against the in-memory DNS provider. Certificates (P1.10) are patched where a test needs one.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.infrastructure.dns_gateway import _DNS_PROVIDER_REGISTRY, register_dns_gateway
from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_full_customer
from tests.helpers.fake_dns_gateway import FakeDnsGateway

ZONE = "praho-sites.net"
ZONE_ID = "0123456789abcdef0123456789abcdef"
DOMAIN = "customer.example.com"
USER = "customer"


class FakeResponse:
    def __init__(self, success: bool, data: dict[str, Any] | None = None, raw: str = "") -> None:
        self.success = success
        self.data = data or {}
        self.raw_response = raw


class FakeNode:
    """One node's domain rows, and every call PRAHO made to it, in order."""

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, str]] = {
            DOMAIN: {
                "domain": DOMAIN,
                "username": USER,
                "type": "Top-level server",
                "parent_domain": "",
                "description": "",
            }
        }
        self.disabled: set[str] = set()
        self.calls: list[str] = []
        self.ambiguous: set[str] = set()

    def list_domains_with_owners(self) -> Any:
        self.calls.append("list")
        return Ok(list(self.rows.values()))

    def get_domain_state(self, domain: str) -> Any:
        if domain not in self.rows:
            return Ok({"exists": False, "enabled": None, "owner": ""})
        return Ok({"exists": True, "enabled": domain not in self.disabled, "owner": self.rows[domain]["username"]})

    def call(self, program: str, params: dict[str, Any], **_: object) -> Any:
        self.calls.append(f"{program} {params.get('domain')}")
        if program in self.ambiguous:
            return Ok(FakeResponse(False, raw="<html>proxy error</html>"))
        if program == "create-domain":
            name = params["domain"]
            if name in self.rows:
                return Ok(
                    FakeResponse(False, raw='{"status": "failure", "error": "You are already hosting this domain"}')
                )
            parent = self.rows[params["parent"]]
            self.rows[name] = {
                "domain": name,
                "username": parent["username"],
                "type": "Sub-server",
                "parent_domain": params["parent"],
                "description": params.get("desc", ""),
            }
            if params["parent"] in self.disabled:
                pass  # A child created under a disabled parent starts ENABLED (lab S10)
            return Ok(FakeResponse(True, {"status": "success"}))
        if program == "disable-domain":
            self.disabled.add(params["domain"])
        elif program == "enable-domain":
            self.disabled.discard(params["domain"])
        elif program == "delete-domain":
            self.rows.pop(params["domain"], None)
        elif program == "list-domains":
            name = params["domain"]
            home = f"/home/{self.rows[name]['username']}/domains/{name}"
            return Ok(FakeResponse(True, {"data": [{"name": name, "values": {"home_directory": [home]}}]}))
        return Ok(FakeResponse(True, {"status": "success"}))


class AccountNameTestCase(TestCase):
    def setUp(self) -> None:
        self.server = VirtualminServer.objects.create(
            name="Node", hostname="node1.example.com", ipv4_address="95.217.0.10", ipv6_address="2a01:4f8::1"
        )
        self.customer = customer = create_full_customer()
        self.currency = currency = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )[0]
        self.plan = plan = ServicePlan.objects.create(
            name="Hosting", plan_type="shared_hosting", price_monthly=Decimal("10.00")
        )
        service_row = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name=DOMAIN,
            domain=DOMAIN,
            username=USER,
            price=Decimal("10.00"),
            status="active",
        )
        self.account = VirtualminAccount.objects.create(
            service=service_row,
            domain=DOMAIN,
            virtualmin_username=USER,
            server=self.server,
            status="active",
            provisioned_at=timezone.now(),
        )
        for key, value in (
            ("dns.account_hostname_zone", ZONE),
            ("dns.account_hostname_zone_id", ZONE_ID),
            ("dns.account_zone_api_token", "token-value"),
        ):
            SettingsService.update_setting(key, value).unwrap()
        self.hostname = service.allocate_account_hostname(self.account)
        self.node = FakeNode()
        gateway = patch.object(service, "_gateway", lambda server: self.node)
        gateway.start()
        self.addCleanup(gateway.stop)
        self.links: list[str] = []
        link = patch.object(
            service,
            "link_account_name_web_root",
            lambda server, *, home, customer_user: (
                self.links.append(home) or self.node.calls.append("link") or Ok(True)
            ),
        )
        link.start()
        self.addCleanup(link.stop)
        certificate = patch.object(
            service, "install_certificate", lambda hostname, server: self.node.calls.append("certificate") or Ok(True)
        )
        certificate.start()
        self.addCleanup(certificate.stop)

    def _psl_shipped(self) -> None:
        SettingsService.update_setting("dns.account_zone_psl_shipped", True).unwrap()


class EnsureTests(AccountNameTestCase):
    def test_an_absent_name_is_created_set_linked_and_certified_in_that_order(self) -> None:
        self._psl_shipped()
        outcome = service.ensure_node_account_name(self.account, self.server, enabled=True).unwrap()
        self.assertEqual((outcome.created, outcome.linked, outcome.certificate_installed), (True, True, True))
        name = self.hostname.fqdn
        steps = [c for c in self.node.calls if c != "list" and not c.startswith("list-domains")]
        self.assertEqual(steps, [f"create-domain {name}", "link", "certificate"])
        self.assertEqual(self.node.rows[name]["parent_domain"], DOMAIN)
        self.assertEqual(self.links, [f"/home/{USER}/domains/{name}"])

    def test_a_name_present_and_owned_is_not_created_again_and_is_linked_again(self) -> None:
        self._psl_shipped()
        service.ensure_node_account_name(self.account, self.server, enabled=True).unwrap()
        self.node.calls.clear()
        outcome = service.ensure_node_account_name(self.account, self.server, enabled=True).unwrap()
        self.assertFalse(outcome.created)
        self.assertNotIn(f"create-domain {self.hostname.fqdn}", self.node.calls)
        self.assertIn("link", self.node.calls)

    def test_a_name_held_by_anything_else_is_refused_and_nothing_changes(self) -> None:
        name = self.hostname.fqdn
        for row in (
            {"type": "Sub-server", "parent_domain": "other.example.com", "username": USER},
            {"type": "Top-level server", "parent_domain": "", "username": USER},
            {"type": "Sub-server", "parent_domain": DOMAIN, "username": "someoneelse"},
        ):
            with self.subTest(row=row):
                self.node.rows[name] = {"domain": name, "description": "", **row}
                self.node.calls.clear()
                result = service.ensure_node_account_name(self.account, self.server, enabled=True)
                self.assertIsInstance(result, Err)
                self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)
                self.assertEqual(self.node.calls, ["list"], "refused before any change")

    def test_a_customer_domain_owned_by_another_user_is_refused(self) -> None:
        self.node.rows[DOMAIN]["username"] = "intruder"
        result = service.ensure_node_account_name(self.account, self.server, enabled=True)
        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_an_ambiguous_create_is_not_success(self) -> None:
        self.node.ambiguous.add("create-domain")
        result = service.ensure_node_account_name(self.account, self.server, enabled=True)
        self.assertIsInstance(result, Err)
        self.assertIs(retriability_of(result), Retriability.UNKNOWN)

    def test_under_a_disabled_parent_the_name_is_disabled_before_it_is_linked(self) -> None:
        self._psl_shipped()
        self.node.disabled.add(DOMAIN)
        outcome = service.ensure_node_account_name(self.account, self.server, enabled=False).unwrap()
        name = self.hostname.fqdn
        self.assertIn(name, self.node.disabled)
        steps = [c for c in self.node.calls if c != "list" and not c.startswith("list-domains")]
        self.assertLess(steps.index(f"disable-domain {name}"), steps.index("link"))
        self.assertFalse(outcome.enabled)

    def test_no_customer_content_before_the_zone_is_a_shipped_public_suffix(self) -> None:
        outcome = service.ensure_node_account_name(self.account, self.server, enabled=True).unwrap()
        self.assertFalse(outcome.linked)
        self.assertEqual(self.links, [])

    def test_remove_deletes_only_an_owned_name(self) -> None:
        service.ensure_node_account_name(self.account, self.server, enabled=True).unwrap()
        name = self.hostname.fqdn
        self.assertEqual(service.remove_node_account_name(self.account, self.server), Ok(True))
        self.assertNotIn(name, self.node.rows)
        self.assertIn(DOMAIN, self.node.rows, "the customer's domain is never touched")
        self.node.rows[name] = {
            "domain": name,
            "username": "someoneelse",
            "type": "Sub-server",
            "parent_domain": DOMAIN,
        }
        result = service.remove_node_account_name(self.account, self.server)
        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertIn(name, self.node.rows)


class SyncTests(AccountNameTestCase):
    def setUp(self) -> None:
        super().setUp()
        previous = _DNS_PROVIDER_REGISTRY.get(service.DNS_PROVIDER)
        register_dns_gateway(service.DNS_PROVIDER, FakeDnsGateway)
        self.addCleanup(lambda: register_dns_gateway(service.DNS_PROVIDER, previous) if previous else None)
        FakeDnsGateway.reset({ZONE_ID: ZONE})
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=self.server)
        self.hostname.refresh_from_db()

    def _enable(self) -> None:
        SettingsService.update_setting("dns.account_hostnames_enabled", True).unwrap()

    def test_nothing_happens_while_the_feature_is_off(self) -> None:
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("disabled"))
        self.assertEqual(FakeDnsGateway.calls, [])

    def test_a_name_without_an_installed_certificate_is_not_published(self) -> None:
        self._enable()
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("skipped:certificate_not_ready"))
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})

    def test_a_ready_name_is_published_to_its_target_server(self) -> None:
        self._enable()
        with patch.object(service, "certificate_ready_on", return_value=True):
            self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {"A": "95.217.0.10", "AAAA": "2a01:4f8::1"})
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records["A"]["applied"], "95.217.0.10")
        self.assertIsNotNone(self.hostname.last_reconciled_at)

    def test_a_token_that_cannot_read_the_zone_or_reads_another_publishes_nothing(self) -> None:
        self._enable()
        for zones in ({}, {ZONE_ID: "other-zone.net"}):
            with self.subTest(zones=zones), patch.object(service, "certificate_ready_on", return_value=True):
                FakeDnsGateway.reset(zones)
                self.assertIsInstance(service.sync_account_hostname(self.hostname), Err)
                self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})

    def test_an_account_not_yet_provisioned_or_terminated_is_not_published(self) -> None:
        self._enable()
        for status, provisioned_at in (("provisioning", None), ("terminated", timezone.now())):
            with self.subTest(status=status), patch.object(service, "certificate_ready_on", return_value=True):
                VirtualminAccount.objects.filter(pk=self.account.pk).update(
                    status=status, provisioned_at=provisioned_at
                )
                self.hostname.refresh_from_db()
                self.assertEqual(service.sync_account_hostname(self.hostname), Ok("skipped:account_not_ready"))

    def test_retiring_deletes_the_records_and_keeps_the_label_taken(self) -> None:
        self._enable()
        with patch.object(service, "certificate_ready_on", return_value=True):
            service.sync_account_hostname(self.hostname).unwrap()
        service.retire_account_hostname(self.hostname).unwrap()
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})
        self.hostname.refresh_from_db()
        self.assertIsNotNone(self.hostname.retired_at)
        self.assertTrue(AccountHostname.objects.filter(label=self.hostname.label).exists(), "the label stays taken")
        with self.assertRaises(service.AccountNameRetiredError):
            service.allocate_account_hostname(self.account)


class AllocationTests(AccountNameTestCase):
    def test_a_label_collision_draws_again(self) -> None:
        second_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="second.example.com",
            domain="second.example.com",
            username="second",
            price=Decimal("10.00"),
            status="active",
        )
        other = VirtualminAccount.objects.create(
            service=second_service, domain="second.example.com", virtualmin_username="second", server=self.server
        )
        draws = iter([*self.hostname.label, *"zz99zz99"])
        with patch.object(service.secrets, "choice", lambda alphabet: next(draws)):
            fresh = service.allocate_account_hostname(other)
        self.assertEqual(fresh.label, "zz99zz99")

    def test_the_same_account_gets_its_existing_name(self) -> None:
        self.assertEqual(service.allocate_account_hostname(self.account), self.hostname)
