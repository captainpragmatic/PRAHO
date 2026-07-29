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
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
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
        """Mock an S3 client holding metadata.json objects under the real key layout."""
        bodies = {f"virtualmin-backups/{o['backup_id']}/metadata.json": json.dumps(o) for o in objects}
        client = MagicMock()
        paginator = MagicMock()

        def _paginate(**kwargs: Any) -> list[dict[str, Any]]:
            prefix = kwargs.get("Prefix", "")
            contents = [{"Key": key} for key in bodies if key.startswith(prefix)]
            return [{"Contents": contents}]

        paginator.paginate.side_effect = _paginate
        client.get_paginator.return_value = paginator

        def _get_object(**kwargs: Any) -> dict[str, Any]:
            body = MagicMock()
            body.read.return_value = bodies[kwargs["Key"]].encode()
            return {"Body": body}

        client.get_object.side_effect = _get_object
        return client

    def _meta(self, backup_id: str, domain: str, **extra: Any) -> dict[str, Any]:
        meta = {
            "backup_id": backup_id,
            "domain": domain,
            "backup_type": "full",
            "created_at": timezone.now().isoformat(),
        }
        meta.update(extra)
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
                self._meta("bk-other", "other.example.com"),
            ]
        )

        backups = self._list(client, account=self.account)

        self.assertEqual([b["backup_id"] for b in backups], ["bk-mine"])

    def test_account_scoped_list_excludes_other_domains(self) -> None:
        """Cross-account leakage would be worse than the empty list it replaces."""
        client = self._s3_with([self._meta("bk-other", "other.example.com")])

        self.assertEqual(self._list(client, account=self.account), [])

    def test_unscoped_list_returns_every_domain(self) -> None:
        client = self._s3_with(
            [
                self._meta("bk-mine", "mine.example.com"),
                self._meta("bk-other", "other.example.com"),
            ]
        )

        backups = self._list(client)

        self.assertEqual({b["backup_id"] for b in backups}, {"bk-mine", "bk-other"})

    def test_account_and_type_filters_compose(self) -> None:
        client = self._s3_with(
            [
                self._meta("bk-full", "mine.example.com", backup_type="full"),
                self._meta("bk-incr", "mine.example.com", backup_type="incremental"),
                self._meta("bk-other-full", "other.example.com", backup_type="full"),
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
