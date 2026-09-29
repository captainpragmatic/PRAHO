"""A domain status change must not call Virtualmin until the transaction commits.

``_handle_domain_status_change_with_virtualmin_sync`` reaches
``gateway.call("disable-domain", ...)`` — a real provider mutation. Fired inline from
``post_save`` it ran inside the caller's still-open transaction, so a rollback left the
control panel disabled while the database said active, with nothing to reconcile it.

Both directions are asserted deliberately. A test that only checks "not called on
rollback" would also pass if synchronisation were broken outright, so the committed
path is asserted too.
"""

from __future__ import annotations

from unittest.mock import patch

from django.db import transaction
from django.test import TestCase

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar, TLDRegistrarAssignment


class _RollbackError(Exception):
    """Marker exception so the rollback is unambiguous."""


class DomainVirtualminSyncCommitBoundaryTests(TestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=2300,
            renewal_price_cents=2300,
            transfer_price_cents=2300,
            min_registration_period=1,
            max_registration_period=10,
            is_active=True,
        )
        self.registrar = Registrar.objects.create(
            name="commit-boundary-registrar",
            display_name="Commit Boundary Registrar",
            website_url="https://example.test",
            status="active",
        )
        TLDRegistrarAssignment.objects.create(tld=self.tld, registrar=self.registrar, is_primary=True)
        self.customer = Customer.objects.create(
            name="Commit Boundary Customer",
            company_name="Commit Boundary SRL",
            customer_type="company",
            primary_email="commit-boundary@example.test",
        )
        self.domain = Domain.objects.create(
            name="commit-boundary.ro",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )

    def test_provider_is_not_called_when_the_enclosing_transaction_rolls_back(self) -> None:
        with patch("apps.domains.signals.sync_domain_to_virtualmin") as sync:
            with self.assertRaises(_RollbackError), self.captureOnCommitCallbacks(execute=True), transaction.atomic():
                self.domain.suspend()
                self.domain.save()
                raise _RollbackError

            sync.assert_not_called()

        self.domain.refresh_from_db()
        self.assertEqual(self.domain.status, "active", "the status change itself must have rolled back too")

    def test_provider_is_called_once_the_change_commits(self) -> None:
        """Guards against 'fixing' the rollback case by breaking sync altogether."""
        with patch("apps.domains.signals.sync_domain_to_virtualmin") as sync:
            with self.captureOnCommitCallbacks(execute=True):
                self.domain.suspend()
                self.domain.save()

            sync.assert_called_once()
            self.assertEqual(sync.call_args.args[0].pk, self.domain.pk)

    def test_the_callback_reloads_rather_than_closing_over_the_instance(self) -> None:
        """Discriminates a pk capture + reload from a lambda that closes over the object.

        The in-memory instance is mutated after the save and before the callbacks drain.
        A closure would hand the provider that mutated object; a reload hands it what
        actually committed. Asserting only `status == "suspended"` cannot tell these
        apart, because both carry that value.
        """
        with patch("apps.domains.signals.sync_domain_to_virtualmin") as sync:
            with self.captureOnCommitCallbacks(execute=True):
                self.domain.suspend()
                self.domain.save()
                # Never saved. A closure would carry this through; a reload discards it.
                self.domain.name = "mutated-after-save.ro"

            synced_domain = sync.call_args.args[0]
            self.assertEqual(
                synced_domain.name,
                "commit-boundary.ro",
                "the callback closed over the in-memory instance instead of reloading committed state",
            )
            self.assertEqual(synced_domain.status, "suspended")

    def test_a_domain_deleted_before_the_callback_runs_is_a_no_op(self) -> None:
        with patch("apps.domains.signals.sync_domain_to_virtualmin") as sync:
            with self.captureOnCommitCallbacks(execute=True):
                self.domain.suspend()
                self.domain.save()
                Domain.objects.filter(pk=self.domain.pk).delete()

            sync.assert_not_called()
