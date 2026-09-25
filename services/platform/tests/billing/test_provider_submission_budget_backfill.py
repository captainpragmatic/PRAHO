"""A column added with `default=0` handed every pre-existing row a fresh retry budget.

`0055` added `ProviderIssuance.submissions` with `default=0`. That satisfies the column and
contradicts all three of its consumers — the sweep's `submissions__lt` filter, `_claim`'s cap
check, and the exhausted gauge's `submissions__gte` count — so a row that had already spent
its POSTs read as brand new, and the operator queue read zero on deploy day.

The backfill is `min(attempts, MAX_SUBMISSIONS)`, and it deliberately over-counts: `attempts`
increments in `claim()` before the rate gate, so a row that was only ever paced looks spent.
That is the cheaper of the two errors. The cap exists to stop futile resubmission against a
rate-limited third party, not to prevent duplicate documents — a refusal earns REJECTED only
from a recognised refusal envelope, and genuine ambiguity goes to `outcome_unknown`, which no
sweep touches and `claim()` has no source edge from.

Over-counting has a cost of its own, and closing it is the other half of the fix. A capped
`pending` row is a state `_finalize` can never produce — it increments `submissions` and then
always lands on ISSUED/FAILED/OUTCOME_UNKNOWN — so both consumers narrowed to `state=FAILED`.
The backfill creates that state for the first time, and until the predicates widen, nothing
lists it: not the gauge, not the queue, and `adopt_provider_document` accepts only
`outcome_unknown`.
"""

from __future__ import annotations

from decimal import Decimal

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance
from apps.billing.issuers.tasks import sweep_pending_issuances
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user
from tests.helpers.migrations import restore_to_leaf

MIGRATE_FROM = ("billing", "0056_repair_credit_note_document_types")
MIGRATION_UNDER_TEST = ("billing", "0057_backfill_provider_submission_budget")


class CappedPendingRowIsVisibleTests(TestCase):
    """The backfill must not park a row where nothing can see it."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _issuance(self, *, state: str, submissions: int, number: str | None = None) -> ProviderIssuance:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        issuance = ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            last_error="Budget spent before the deploy",
        )
        ProviderIssuance.objects.filter(pk=issuance.pk).update(state=state, submissions=submissions)
        return issuance

    def test_a_capped_pending_row_is_counted_by_the_exhausted_gauge(self) -> None:
        self._issuance(state=IssuanceState.PENDING.value, submissions=MAX_SUBMISSIONS)

        result = sweep_pending_issuances()

        self.assertEqual(result["exhausted"], 1)
        self.assertEqual(result["queued"], 0)

    def test_a_capped_pending_row_is_listed_on_the_reconciliation_queue(self) -> None:
        self._issuance(state=IssuanceState.PENDING.value, submissions=MAX_SUBMISSIONS)
        self.client.force_login(create_admin_user(username="budget_queue"))

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertContains(response, "Budget spent before the deploy")

    def test_a_capped_failed_row_is_still_counted(self) -> None:
        """The narrower predicate this widens must keep working."""
        self._issuance(state=IssuanceState.FAILED.value, submissions=MAX_SUBMISSIONS)

        self.assertEqual(sweep_pending_issuances()["exhausted"], 1)

    def test_a_numbered_row_is_not_exhausted(self) -> None:
        """A document that got its number needs nothing, whatever it spent getting there."""
        self._issuance(state=IssuanceState.PENDING.value, submissions=MAX_SUBMISSIONS, number="FCT-000801")

        self.assertEqual(sweep_pending_issuances()["exhausted"], 0)

    def test_an_under_budget_pending_row_is_swept_not_quarantined(self) -> None:
        self._issuance(state=IssuanceState.PENDING.value, submissions=MAX_SUBMISSIONS - 1)

        result = sweep_pending_issuances()

        self.assertEqual(result["exhausted"], 0)
        self.assertEqual(result["queued"] + result["skipped"], 1)


class SubmissionBudgetBackfillMigrationTest(TransactionTestCase):
    """A deployment that already applied 0055 holds the zeroed rows right now."""

    def tearDown(self) -> None:
        restore_to_leaf("billing")
        super().tearDown()

    def _seed(self, rows: list[dict[str, object]]) -> list[object]:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old = executor.loader.project_state([MIGRATE_FROM]).apps

        customer_model = old.get_model("customers", "Customer")
        currency_model = old.get_model("billing", "Currency")
        invoice_model = old.get_model("billing", "Invoice")
        issuance_model = old.get_model("billing", "ProviderIssuance")

        customer = customer_model.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active"
        )
        currency, _ = currency_model.objects.get_or_create(
            code="RON", defaults={"symbol": "L", "decimals": 2, "name": "Romanian Leu"}
        )

        pks = []
        for index, row in enumerate(rows):
            invoice = invoice_model.objects.create(
                customer=customer,
                currency=currency,
                number=row.get("number"),
                status="draft",
                subtotal_cents=10000,
                tax_cents=2100,
                total_cents=12100,
                bill_to_name="Test Co",
                bill_to_country="RO",
                issuer_provider="smartbill",
            )
            issuance = issuance_model.objects.create(
                invoice=invoice,
                provider="smartbill",
                state=row.get("state", "failed"),
                attempts=row["attempts"],
                submissions=row.get("submissions", 0),
                request_hash=f"hash{index}",
            )
            pks.append(issuance.pk)
        return pks

    def _submissions_after_migration(self, pks: list[object]) -> list[int]:
        MigrationExecutor(connection).migrate([MIGRATION_UNDER_TEST])
        new = MigrationExecutor(connection).loader.project_state([MIGRATION_UNDER_TEST]).apps
        model = new.get_model("billing", "ProviderIssuance")
        return [int(model.objects.get(pk=pk).submissions) for pk in pks]

    def test_a_row_over_the_cap_is_capped_not_multiplied(self) -> None:
        pks = self._seed([{"attempts": 7}])

        self.assertEqual(self._submissions_after_migration(pks), [MAX_SUBMISSIONS])

    def test_a_row_under_the_cap_carries_its_own_count(self) -> None:
        pks = self._seed([{"attempts": 2}])

        self.assertEqual(self._submissions_after_migration(pks), [2])

    def test_a_row_that_never_attempted_stays_at_zero(self) -> None:
        pks = self._seed([{"attempts": 0}])

        self.assertEqual(self._submissions_after_migration(pks), [0])

    def test_a_numbered_row_is_left_alone(self) -> None:
        """It already has its document; spending its budget would only hide it."""
        pks = self._seed([{"attempts": 5, "number": "FCT-000802", "state": "issued"}])

        self.assertEqual(self._submissions_after_migration(pks), [0])

    def test_a_row_with_a_real_count_is_not_overwritten(self) -> None:
        """Re-running must be stable, and must never lower a genuine count."""
        pks = self._seed([{"attempts": 9, "submissions": 1}])

        self.assertEqual(self._submissions_after_migration(pks), [1])
