"""The adoption form accepted any string into a legally immutable, unique column.

`series` and `number` are what an operator reads off the provider's screen, and what PRAHO
then writes into `Invoice.number` - a `unique=True` fiscal field that cannot be changed
afterwards. Both were bare `CharField`s.

The sibling usually cited here guards a different thing. `InvoiceSeriesForm.prefix` is
`^[A-Z0-9][A-Z0-9-]{0,29}$`, and it governs `InvoiceSequence.prefix` - a string PRAHO
GENERATES. This one carries a string PRAHO ACCEPTS from a third party and must reproduce
verbatim, which is `d390.py`'s category: `[A-Za-z0-9 +.@-]+\\Z`, the charset the pinned ANAF
annex permits for text emitted into a filing.

Two things borrowed from the prefix guard would be bugs here, and both are pinned below.

`.upper()` would corrupt the number. SmartBill is case-significant on account-coupled names -
stated at `smartbill/mapper.py` and in the settings catalog, and enforced by an exact
membership test in preflight - so upper-casing a lowercase series writes a WRONG legal number
into a column nothing can correct.

The 29-character bound is the local prefix's length. `provider_series` and `provider_number`
are `max_length=50`.

And the direction of failure is the opposite of the migration backfill's, deliberately. This
screen is the only exit from `outcome_unknown`, so over-rejecting strands the invoice forever.
A regex cannot catch a mistyped digit anyway; its job is narrow - control characters, a newline
carried in by a paste, a non-ASCII homoglyph. The double-entry `confirmation` field and the
composed-length check remain the real guards.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.billing.forms import ProviderReconciliationForm


def _data(**overrides: str) -> dict[str, str]:
    data = {
        "series": "FCT",
        "number": "0000123",
        "confirmation": "0000123",
        "reason": "Found it in the SmartBill web UI under today's date.",
    }
    data.update(overrides)
    return data


class ProviderReconciliationCharsetTests(SimpleTestCase):
    # --- what must now be refused -------------------------------------------------

    def test_a_newline_in_the_number_is_refused(self) -> None:
        """What a paste from a provider's web UI carries in."""
        form = ProviderReconciliationForm(data=_data(number="0000123\n0000124", confirmation="0000123\n0000124"))

        self.assertFalse(form.is_valid())
        self.assertIn("number", form.errors)

    def test_a_control_character_in_the_number_is_refused(self) -> None:
        form = ProviderReconciliationForm(data=_data(number="00001\x0723", confirmation="00001\x0723"))

        self.assertFalse(form.is_valid())
        self.assertIn("number", form.errors)

    def test_a_non_ascii_homoglyph_in_the_series_is_refused(self) -> None:
        """A Cyrillic capital TE is a different series that renders identically to a Latin T.

        Built with `chr` rather than written out: ruff refuses an ambiguous character in a
        literal, which is the same instinct this test is checking the form now has.
        """
        cyrillic_te = chr(0x0422)
        form = ProviderReconciliationForm(data=_data(series=f"FC{cyrillic_te}"))

        self.assertFalse(form.is_valid())
        self.assertIn("series", form.errors)

    def test_a_non_breaking_space_is_refused(self) -> None:
        """It survives `.strip()`, so it would reach the column."""
        form = ProviderReconciliationForm(data=_data(series=f"FCT{chr(0x00A0)}"))

        self.assertFalse(form.is_valid())
        self.assertIn("series", form.errors)

    # --- what must still be allowed ------------------------------------------------

    def test_the_recorded_live_shape_is_accepted(self) -> None:
        """`{"errorText": "", "number": "3593", "series": "FCT"}` is a real recorded reply."""
        form = ProviderReconciliationForm(data=_data(series="FCT", number="3593", confirmation="3593"))

        self.assertTrue(form.is_valid(), form.errors)

    def test_a_lowercase_series_is_kept_lowercase(self) -> None:
        """SmartBill is case-significant; `.upper()` here would write a wrong legal number."""
        form = ProviderReconciliationForm(data=_data(series="fct"))

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["series"], "fct")

    def test_a_blank_series_is_accepted(self) -> None:
        """A provider with no series at all is the documented case for this field."""
        form = ProviderReconciliationForm(data=_data(series="", number="3593", confirmation="3593"))

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["series"], "")

    def test_the_d390_punctuation_is_accepted(self) -> None:
        """Nothing in the repo evidences SmartBill's charset, so it is not narrowed further."""
        for series in ("FCT-2026", "FCT.A", "A B", "FCT+1", "a@b"):
            with self.subTest(series=series):
                form = ProviderReconciliationForm(data=_data(series=series))

                self.assertTrue(form.is_valid(), form.errors)

    def test_a_fifty_character_number_is_accepted(self) -> None:
        """The column is 50; the 29-character bound belongs to the local prefix."""
        number = "9" * 50
        form = ProviderReconciliationForm(data=_data(series="", number=number, confirmation=number))

        self.assertTrue(form.is_valid(), form.errors)
