"""An account name is a sub-server of the customer domain; listings tell it apart (ADR-0061 P1.6).

`list-domains` returns the account name as its own row (`type: Sub-server`, `parent_domain`). Views
that show or count customer domains leave it out: the account sync must not import it as an
account, and server statistics must not count it. Safety checks keep every row: a collision check
or a restore gate that skipped sub-servers could reuse a name that exists. Migration admits an
account whose only extra row is its own verified account-name child, and refuses any other.

The sub-server row is derived from the recorded 8.3 top-level row with the two fields the lab
proved (`docs/domain/virtualmin-account-subserver-contract.md`, S8).
"""

from __future__ import annotations

import copy
from typing import Any

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_gateway import is_customer_domain_row
from apps.provisioning.virtualmin_migration_service import owned_customer_rows
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminServerManagementService
from tests.helpers.recorded_virtualmin import load_cases
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture

ZONE = "acct.praho.test"
LABEL = "h7k3p2q9"


def _recorded_row(name: str, username: str) -> dict[str, Any]:
    row = copy.deepcopy(load_cases("list-domains")["all_domains"]["body"]["data"][0])
    row["name"] = name
    row["values"]["username"] = [username]
    return row


def _sub_server_row(name: str, parent: str, username: str) -> dict[str, Any]:
    row = _recorded_row(name, username)
    row["values"]["type"] = ["Sub-server"]
    row["values"]["parent_domain"] = [parent]
    return row


class RowKindTests(SimpleTestCase):
    def test_a_top_level_row_and_an_untyped_row_are_customer_domains(self) -> None:
        self.assertTrue(is_customer_domain_row({"domain": "a.example.com", "type": "Top-level server"}))
        self.assertTrue(is_customer_domain_row({"domain": "a.example.com", "type": ""}))

    def test_a_sub_server_or_alias_row_is_not(self) -> None:
        self.assertFalse(is_customer_domain_row({"domain": f"{LABEL}.{ZONE}", "type": "Sub-server"}))
        self.assertFalse(is_customer_domain_row({"domain": "alias.example.com", "type": "Alias of example.com"}))


class SyncSkipsAccountNamesTests(VirtualminViewsFixture):
    def test_the_sync_does_not_import_an_account_name_as_a_domain_or_an_account(self) -> None:
        name = f"{LABEL}.{ZONE}"
        self.payload["data"] = [
            _recorded_row(self.account.domain, self.account.virtualmin_username),
            _sub_server_row(name, self.account.domain, self.account.virtualmin_username),
        ]
        for row in self.payload["data"]:
            row["values"]["status"] = ["Enabled"]
            row["values"].pop("disabled", None)
        self.client.post(reverse("provisioning:virtualmin_accounts_sync"))

        self.account.refresh_from_db()
        self.assertEqual(self.account.domains, [self.account.domain])
        self.assertFalse(VirtualminAccount.objects.filter(domain=name).exists())


class StatisticsSkipAccountNamesTests(VirtualminServiceCoverageCase):
    def test_server_statistics_count_customer_domains_only(self) -> None:
        self.payloads["list-domains"] = {
            "status": "success",
            "data": [
                _recorded_row("one.example.com", "one"),
                _recorded_row("two.example.com", "two"),
                _sub_server_row(f"{LABEL}.{ZONE}", "one.example.com", "one"),
            ],
        }
        result = VirtualminServerManagementService().update_server_statistics(self.server)
        self.assertEqual(result.unwrap()["domain_count"], 2)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 2)


class MigrationAdmissionTests(TestCase):
    """The source owner's rows: the account's domain, plus at most its own verified account-name child."""

    def setUp(self) -> None:
        self.account = VirtualminAccount(domain="customer.example.com", virtualmin_username="customer")
        self.child = {
            "domain": f"{LABEL}.{ZONE}",
            "username": "customer",
            "type": "Sub-server",
            "parent_domain": "customer.example.com",
        }
        self.own = {"domain": "customer.example.com", "username": "customer", "type": "Top-level server"}

    def _names(self) -> set[str]:
        return {f"{LABEL}.{ZONE}"}

    def test_the_account_alone_is_admitted(self) -> None:
        self.assertEqual(owned_customer_rows([self.own], self.account, set()), [self.own])

    def test_its_own_verified_account_name_child_is_admitted(self) -> None:
        self.assertEqual(owned_customer_rows([self.own, self.child], self.account, self._names()), [self.own])

    def test_any_other_extra_row_is_refused(self) -> None:
        extra_site = {**self.child, "domain": "blog.customer.example.com"}
        wrong_parent = {**self.child, "parent_domain": "other.example.com"}
        top_level_name = {**self.child, "type": "Top-level server"}
        for rows, names in (
            ([self.own, extra_site], self._names()),  # another sub-site: the parent-only archive would drop it
            ([self.own, wrong_parent], self._names()),
            ([self.own, top_level_name], self._names()),
            ([self.own, self.child], set()),  # a child that is not this account's live name
        ):
            with self.subTest(rows=[row["domain"] for row in rows]), self.assertRaises(ValueError):
                owned_customer_rows(rows, self.account, names)


class SafetyChecksSeeEveryRowTests(VirtualminServiceCoverageCase):
    def test_the_collision_check_still_sees_a_sub_server_named_like_the_new_domain(self) -> None:
        from apps.provisioning.virtualmin_service import VirtualminProvisioningService  # noqa: PLC0415

        account = VirtualminAccount(domain="taken.example.com", virtualmin_username="newuser")
        self.payloads["list-domains"] = {
            "status": "success",
            "data": [_sub_server_row("taken.example.com", "someone.example.com", "someone")],
        }
        service = VirtualminProvisioningService()
        result = service._check_domain_conflicts(account, service._get_gateway(self.server))
        self.assertTrue(result.is_err())
        self.assertIn("already exists", result.unwrap_err())

    def test_the_restore_target_gate_still_sees_a_sub_server_named_like_the_account(self) -> None:
        from apps.provisioning.virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415

        account = VirtualminAccount(domain="restore.example.com", virtualmin_username="restoreuser")
        self.payloads["list-domains"] = {
            "status": "success",
            "data": [_sub_server_row("restore.example.com", "someone.example.com", "someone")],
        }
        result = VirtualminBackupService(self.server)._target_domain_gate(self.server, account, force=True)
        self.assertTrue(result.is_err())
        self.assertIn("foreign ownership", result.unwrap_err())


class AccountHostnameNamesTests(TestCase):
    def test_live_names_of_an_account_are_its_label_in_the_zone(self) -> None:
        from apps.provisioning.virtualmin_migration_service import account_name_children  # noqa: PLC0415

        hostname = AccountHostname.objects.create(label=LABEL, zone=ZONE)
        self.assertEqual(account_name_children(hostname), {f"{LABEL}.{ZONE}"})
        self.assertEqual(account_name_children(None), set())
