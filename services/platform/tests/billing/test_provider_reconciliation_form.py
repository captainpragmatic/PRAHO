"""The form that turns a human's reading of a provider screen into a legal number.

It guards the only unchangeable thing on this path: `Invoice.number`, which cannot be
edited once adopted. Nothing tested it.

Two guards live here. The confirmation field is double entry against a misread digit.
The length check is against a composition the field limits do not see: `series` and
`number` are validated separately, and the service joins them.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.billing.forms import ProviderReconciliationForm
from apps.billing.invoice_models import Invoice

_REASON = "Checked SmartBill Cloud; found this document for the customer."


def _payload(**overrides: str) -> dict[str, str]:
    data = {"series": "FCT", "number": "000900", "confirmation": "000900", "reason": _REASON}
    data.update(overrides)
    return data


class CompositeNumberLengthTests(SimpleTestCase):
    def test_a_composed_number_longer_than_the_column_is_refused(self) -> None:
        """`series` and `number` each fit; `series-number` does not.

        `reconcile_confirmed_issued` joins them and writes the result to `Invoice.number`,
        a varchar(50). A 30-character series with a 50-character number composes to 81 and
        raises a database DataError on PostgreSQL - a 500 rather than a field error,
        leaving that reconciliation unusable. SQLite does not enforce the width, which is
        why the suite never saw it.
        """
        number = "9" * 50
        form = ProviderReconciliationForm(data=_payload(series="S" * 30, number=number, confirmation=number))

        self.assertFalse(form.is_valid())
        self.assertIn("number", form.errors, f"the error must name a field the operator can fix; got {form.errors}")

    def test_a_number_that_exactly_fills_the_column_is_accepted(self) -> None:
        """The boundary, so the check cannot be off by one."""
        limit = Invoice._meta.get_field("number").max_length
        assert limit is not None
        number = "9" * (limit - len("FCT-"))
        form = ProviderReconciliationForm(data=_payload(number=number, confirmation=number))

        self.assertTrue(form.is_valid(), form.errors)

    def test_a_blank_series_is_not_counted_as_a_separator(self) -> None:
        """With no series the service writes the number alone, so no hyphen is spent."""
        limit = Invoice._meta.get_field("number").max_length
        assert limit is not None
        number = "9" * limit
        form = ProviderReconciliationForm(data=_payload(series="", number=number, confirmation=number))

        self.assertTrue(form.is_valid(), form.errors)


class DoubleEntryConfirmationTests(SimpleTestCase):
    """Untested until now, though it guards a number that cannot be changed afterwards."""

    def test_a_mismatched_confirmation_is_refused(self) -> None:
        form = ProviderReconciliationForm(data=_payload(confirmation="000901"))

        self.assertFalse(form.is_valid())
        self.assertIn("confirmation", form.errors)

    def test_a_matching_confirmation_is_accepted(self) -> None:
        self.assertTrue(ProviderReconciliationForm(data=_payload()).is_valid())

    def test_whitespace_does_not_defeat_the_comparison(self) -> None:
        """`clean_number` strips, so the confirmation must be compared against the
        stripped value rather than the raw one."""
        form = ProviderReconciliationForm(data=_payload(number="  000900  "))

        self.assertTrue(form.is_valid(), form.errors)
