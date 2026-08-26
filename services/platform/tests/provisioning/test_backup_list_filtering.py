"""#431: an account-scoped backup list must actually return that account's backups.

``list_backups(account=...)`` narrowed the S3 *prefix* to
``virtualmin-backups/{account.domain}/``, but archives and metadata are stored under
``virtualmin-backups/{backup_id}/``. The prefix matched no key, so an account-scoped
list always returned an empty list — indistinguishable from "this account has no
backups", which is the dangerous reading: an operator checking restore options for a
customer would be told there is nothing to restore.

There was no test for ``list_backups`` at all, which is why an always-empty result
went unnoticed.
"""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import BackupConfig, VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer


class ListBackupsAccountFilterTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="List Customer", primary_email="ls@example.com", customer_type="individual"
        )
        self.plan = ServicePlan.objects.create(
            name="LS Plan", plan_type="shared_hosting", price_monthly=Decimal("10.00"), setup_fee=Decimal("0.00")
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="ls-svc",
            username="lsuser",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="ls-server", hostname="ls.example.com", api_username="api", max_domains=1000
        )
        self.server.set_api_password("pw")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            domain="mine.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="lsacct",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )
        self.svc = VirtualminBackupService(self.server)

    def _s3_with(self, objects: list[dict[str, Any]]) -> MagicMock:
        """Mock an S3 client mirroring the real bucket, not a convenient subset.

        Every backup contributes BOTH keys the writer creates — metadata.json AND the
        sibling backup.tar.gz. The archive body is a poison MagicMock whose read()
        raises: if the listing loop ever loses its ``.endswith(".json")`` guard, it
        would pull whole archives into the web worker — the poison makes that a loud
        failure here instead of a silent green. Listing is also served in pages of
        two keys, because real list_objects_v2 paginates and a first-page-only
        regression must not ship.
        """
        bodies: dict[str, Any] = {}
        for o in objects:
            bodies[f"virtualmin-backups/{o['backup_id']}/metadata.json"] = json.dumps(o).encode()
            poison = MagicMock()
            poison.read.side_effect = AssertionError("listing must never read an archive body")
            bodies[f"virtualmin-backups/{o['backup_id']}/backup.tar.gz"] = poison
        client = MagicMock()
        paginator = MagicMock()

        def _paginate(**kwargs: Any) -> list[dict[str, Any]]:
            prefix = kwargs.get("Prefix", "")
            keys = sorted(key for key in bodies if key.startswith(prefix))
            page_size = 2
            return [
                {"Contents": [{"Key": k} for k in keys[i : i + page_size]]}
                for i in range(0, len(keys), page_size)
            ] or [{}]

        paginator.paginate.side_effect = _paginate
        client.get_paginator.return_value = paginator

        def _get_object(**kwargs: Any) -> dict[str, Any]:
            body = bodies[kwargs["Key"]]
            if isinstance(body, bytes):
                reader = MagicMock()
                reader.read.return_value = body
                return {"Body": reader}
            return {"Body": body}  # the poison archive body

        client.get_object.side_effect = _get_object
        return client

    def _meta(self, backup_id: str, domain: str, **extra: Any) -> dict[str, Any]:
        meta = {
            "backup_id": backup_id,
            "domain": domain,
            "backup_type": "full",
            "created_at": timezone.now().isoformat(),
            # The stable identity the account filter matches on. Overridable per test;
            # pass praho_service_id=None to simulate unattributable legacy metadata.
            "praho_service_id": str(self.service.id),
        }
        meta.update(extra)
        if meta.get("praho_service_id") is None:
            meta.pop("praho_service_id")
        return meta

    def _list(self, client: MagicMock, **kwargs: Any) -> list[dict[str, Any]]:
        with (
            patch.object(self.svc, "_get_s3_client", return_value=client),
            patch.object(self.svc, "_get_backup_bucket", return_value="bucket"),
        ):
            result = self.svc.list_backups(**kwargs)
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def test_account_scoped_list_returns_that_accounts_backups(self) -> None:
        """The regression: this returned [] because the prefix matched no key."""
        client = self._s3_with(
            [
                self._meta("bk-mine", "mine.example.com"),
                self._meta("bk-other", "other.example.com", praho_service_id="11111111-2222-3333-4444-555555555555"),
            ]
        )

        backups = self._list(client, account=self.account)

        self.assertEqual([b["backup_id"] for b in backups], ["bk-mine"])

    def test_account_scoped_list_excludes_other_domains(self) -> None:
        """Cross-account leakage would be worse than the empty list it replaces."""
        client = self._s3_with([self._meta("bk-other", "other.example.com", praho_service_id="11111111-2222-3333-4444-555555555555")])

        self.assertEqual(self._list(client, account=self.account), [])

    def test_unscoped_list_returns_every_domain(self) -> None:
        client = self._s3_with(
            [
                self._meta("bk-mine", "mine.example.com"),
                self._meta("bk-other", "other.example.com", praho_service_id="11111111-2222-3333-4444-555555555555"),
            ]
        )

        backups = self._list(client)

        self.assertEqual({b["backup_id"] for b in backups}, {"bk-mine", "bk-other"})

    def test_account_and_type_filters_compose(self) -> None:
        client = self._s3_with(
            [
                self._meta("bk-full", "mine.example.com", backup_type="full"),
                self._meta("bk-incr", "mine.example.com", backup_type="incremental"),
                self._meta("bk-other-full", "other.example.com", backup_type="full", praho_service_id="11111111-2222-3333-4444-555555555555"),
            ]
        )

        backups = self._list(client, account=self.account, backup_type="full")

        self.assertEqual([b["backup_id"] for b in backups], ["bk-full"])

    def test_age_filter_still_applies_to_an_account_scoped_list(self) -> None:
        old = (timezone.now() - timedelta(days=90)).isoformat()
        client = self._s3_with(
            [
                self._meta("bk-recent", "mine.example.com"),
                self._meta("bk-old", "mine.example.com", created_at=old),
            ]
        )

        backups = self._list(client, account=self.account, max_age_days=30)

        self.assertEqual([b["backup_id"] for b in backups], ["bk-recent"])

    def test_metadata_without_a_domain_is_not_attributed_to_an_account(self) -> None:
        """Fail closed: an unattributable archive must not appear as this customer's."""
        client = self._s3_with([{"backup_id": "bk-nodomain", "created_at": timezone.now().isoformat()}])

        self.assertEqual(self._list(client, account=self.account), [])

    def test_backups_survive_a_domain_rename(self) -> None:
        """Identity is the stable service id, not the reusable domain name.

        After a primary-domain change, this account's earlier backups carry the OLD
        domain in their metadata. Matching on domain would hide them — the same
        "nothing to restore" failure this fix exists to end, reopened by a rename.
        """
        client = self._s3_with([self._meta("bk-prerename", "old-name.example.com")])

        backups = self._list(client, account=self.account)

        self.assertEqual([b["backup_id"] for b in backups], ["bk-prerename"])

    def test_recycled_domain_does_not_expose_the_previous_owners_backups(self) -> None:
        """The cross-customer leak: a domain deleted by customer A and re-registered
        by customer B must NOT surface A's backups in B's account-scoped list —
        metadata carries B's exact domain here, but a FOREIGN service id.
        """
        client = self._s3_with(
            [self._meta("bk-prev-owner", "mine.example.com", praho_service_id="11111111-2222-3333-4444-555555555555")]
        )

        self.assertEqual(self._list(client, account=self.account), [])

    def test_metadata_without_a_service_id_is_excluded_fail_closed(self) -> None:
        """Legacy/unattributable metadata (no praho_service_id) must not be attributed
        to ANY account — even when its domain matches exactly."""
        client = self._s3_with([self._meta("bk-legacy", "mine.example.com", praho_service_id=None)])

        self.assertEqual(self._list(client, account=self.account), [])

    def test_service_id_comparison_is_type_insensitive(self) -> None:
        """JSON round-trips UUIDs as strings; the account side holds a UUID object."""
        client = self._s3_with([self._meta("bk-strsid", "mine.example.com", praho_service_id=str(self.service.id))])

        backups = self._list(client, account=self.account)

        self.assertEqual([b["backup_id"] for b in backups], ["bk-strsid"])

    def test_initialized_metadata_is_json_serializable(self) -> None:
        """The initializer must emit praho_service_id as a STRING.

        The account filter compares str()-normalized ids, and the upload path is a
        bare json.dumps: emitting the raw pk keeps working while Service.pk is a
        BigAutoField but silently breaks (TypeError, no metadata uploaded at all) if
        the pk ever becomes a UUID like most models here — and a raw-int emission
        makes every reader carry int-vs-str comparison traps. Never source this from
        account.praho_service_id: that UUIDField holds an int-coerced UUID that will
        never equal the real service pk.
        """
        metadata = self.svc._initialize_backup_metadata(self.account, "full", "bk-ser", BackupConfig())

        serialized = json.dumps(metadata)  # must not raise
        self.assertEqual(json.loads(serialized)["praho_service_id"], str(self.service.id))
