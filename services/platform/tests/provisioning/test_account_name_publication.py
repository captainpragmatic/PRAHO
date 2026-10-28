"""Every publisher of an account name's records decides on the row it holds locked (ADR-0061 P2, invariant 3).

A caller holding an older copy of the name, like the sweep, never publishes a node the name has left
nor a name retired meanwhile. The intent is committed before the provider call, so a worker killed
during it still leaves the name withdrawable. Records are merged: what was learned about a record is
kept while its content is unchanged.
"""

from __future__ import annotations

import ast
import threading
import time
from pathlib import Path
from unittest.mock import patch

from django.db import connection, transaction
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_account_hostname_service import AccountNameTestCase, AccountNameTransactionCase

PROVISIONING = Path(service.__file__).resolve().parent
PROVIDER_MUTATIONS = {"reconcile_records", "delete_owned_records", "reconcile_txt_values", "sweep_owned_records"}
# The functions that change the name's A and AAAA records, each under the name's row lock, and the
# certificate's challenge TXT records, which are not routing and stay under the order's own claim.
PUBLISHERS = {
    ("account_hostname_service", "_publish"),
    ("account_hostname_service", "_withdraw"),
    ("account_hostname_service", "_record_outcome"),
    ("account_hostname_service", "retire_account_hostname"),
    ("account_name_certificates", "_publish_challenges"),
    ("account_name_certificates", "_clean_challenges"),
    ("account_name_certificates", "sweep_stale_challenge_records"),
}


def _second_node(*, ipv6: str = "2a01:4f8::2") -> VirtualminServer:
    return VirtualminServer.objects.create(
        name="Target", hostname="node2.example.com", ipv4_address="95.217.0.20", ipv6_address=ipv6
    )


def _ready(case: AccountNameTransactionCase) -> None:
    """The name targets the first node, and a certificate is installed wherever it points."""
    AccountHostname.objects.filter(pk=case.hostname.pk).update(target_server=case.server)
    case.hostname.refresh_from_db()
    ready = patch.object(service, "certificate_ready_on", return_value=True)
    ready.start()
    case.addCleanup(ready.stop)


class StaleCallerTests(AccountNameTestCase):
    def setUp(self) -> None:
        super().setUp()
        _ready(self)

    def test_a_stale_copy_publishes_the_node_the_row_names_now(self) -> None:
        stale = AccountHostname.objects.get(pk=self.hostname.pk)
        target = _second_node()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)  # the cutover's commit

        self.assertEqual(service.sync_account_hostname(stale), Ok("published"))

        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {"A": "95.217.0.20", "AAAA": "2a01:4f8::2"})

    def test_a_stale_copy_publishes_nothing_for_a_name_retired_meanwhile(self) -> None:
        stale = AccountHostname.objects.get(pk=self.hostname.pk)
        AccountHostname.objects.filter(pk=self.hostname.pk).update(retired_at=timezone.now())

        self.assertEqual(service.sync_account_hostname(stale), Ok("skipped:retired"))

        self.assertFalse([call for call in FakeDnsGateway.calls if call.startswith("reconcile")])

    def test_a_worker_killed_after_the_provider_applied_leaves_the_name_withdrawable(self) -> None:
        with (
            patch.object(service, "_record_outcome", side_effect=RuntimeError("worker killed")),
            self.assertRaises(RuntimeError),
        ):
            service.sync_account_hostname(self.hostname)
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn)["A"], "95.217.0.10", "the provider applied")
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records["A"]["intended"], "95.217.0.10")

        with patch.object(service, "certificate_ready_on", return_value=False):
            self.assertEqual(service.sync_account_hostname(self.hostname), Ok("withdrawn"))

        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})


class MergedRecordsTests(AccountNameTestCase):
    def setUp(self) -> None:
        super().setUp()
        _ready(self)
        service.sync_account_hostname(self.hostname).unwrap()
        self.hostname.refresh_from_db()
        records = self.hostname.records
        for record_type in ("A", "AAAA"):
            records[record_type]["verified_at"] = "2026-10-19T10:00:00+00:00"
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records=records)

    def test_unchanged_content_keeps_what_was_learned_about_it(self) -> None:
        service.sync_account_hostname(self.hostname).unwrap()

        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records["A"]["verified_at"], "2026-10-19T10:00:00+00:00")
        self.assertEqual(self.hostname.records["A"]["applied"], "95.217.0.10")

    def test_changed_content_forgets_it_and_a_type_no_longer_intended_is_dropped(self) -> None:
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=_second_node(ipv6=""))

        service.sync_account_hostname(self.hostname).unwrap()

        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records["A"]["applied"], "95.217.0.20")
        self.assertNotIn("verified_at", self.hostname.records["A"])
        self.assertNotIn("AAAA", self.hostname.records)


class OnePublicationPathTests(AccountNameTestCase):
    def test_only_the_locked_publishers_change_provider_records(self) -> None:
        found = set()
        for path in PROVISIONING.glob("*.py"):
            tree = ast.parse(path.read_text())
            for function in ast.walk(tree):
                if not isinstance(function, ast.FunctionDef):
                    continue
                for node in ast.walk(function):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in PROVIDER_MUTATIONS
                    ):
                        found.add((path.stem, function.name))
        self.assertEqual(found, PUBLISHERS)


class PublicationLockTests(AccountNameTransactionCase):
    """On PostgreSQL a publisher waits for the lock the cutover's commit holds, then publishes its node."""

    def test_a_sync_waiting_on_the_commit_publishes_the_new_node(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        _ready(self)
        target = _second_node()
        stale = AccountHostname.objects.get(pk=self.hostname.pk)
        locked = threading.Event()
        outcome: list[object] = []

        def sweep() -> None:
            locked.wait(5)
            try:
                outcome.append(service.sync_account_hostname(stale))
            finally:
                connection.close()

        thread = threading.Thread(target=sweep)
        thread.start()
        with transaction.atomic():
            service.lock_for_publication(self.hostname.pk)  # The commit's lock
            locked.set()
            time.sleep(0.5)
            self.assertEqual(outcome, [], "the sync must wait for the commit")
            AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)
        thread.join(10)

        self.assertEqual(outcome, [Ok("published")])
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn)["A"], "95.217.0.20")

    def test_the_sweep_skips_a_name_being_published_instead_of_waiting(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        _ready(self)
        outcome: list[object] = []

        def sweep() -> None:
            try:
                outcome.append(service.sync_account_hostname(self.hostname, skip_locked=True))
            finally:
                connection.close()

        with transaction.atomic():
            service.lock_for_publication(self.hostname.pk)
            thread = threading.Thread(target=sweep)
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "the sweep must not wait for the lock")

        self.assertEqual(outcome, [Ok("skipped:busy")])
