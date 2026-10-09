"""The refund forms and the refund record must agree on what a reason is.

They did not. The four staff selects and the portal's customer-facing one offered eleven
reasons; only three were valid ``REASON_CHOICES`` values. Django does not run
``full_clean()`` on ``objects.create()``, so the other eight were written and kept — a refund
reading "Quality Not As Expected" or "Duplicate Invoice" carried a value no filter, report or
``get_reason_display()`` could match, and nothing ever failed loudly.

Six of those terms are now real choices. Three were different spellings of choices that
already existed (``dispute_resolution``≡``dispute``, ``cancellation_request``≡``cancellation``,
``duplicate_invoice``/``duplicate_order``≡``duplicate_payment``) — adding both spellings would
have put synonym pairs in a choices field and split every future report across them, so the
templates were corrected and the old history's migration 0048 repaired the stored rows.

The template scan below is the durable part: it is the test that would have caught this on the
day the vocabularies diverged.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

from apps.billing.refund_models import Refund
from apps.billing.refund_service import RefundReason

REPO_ROOT = Path(__file__).resolve().parents[4]

# Every select whose value becomes ``Refund.reason``, identified by element id because the
# *names* do not distinguish them. Refunds are staff-only, so these two staff dialogs are the
# complete inventory: the portal's customer select was removed with the customer refund path.
REFUND_REASON_SELECTS = (
    ("services/platform/templates/billing/invoice_detail.html", "invoice_refund_reason"),
    ("services/platform/templates/orders/order_detail.html", "refund_reason"),
)

# The selects that look identical but feed a different domain: they POST to
# ``*_refund_request``, which opens a support ticket and never creates a Refund. Their values
# are keys into ``reason_titles`` maps in those views, so they answer to that map, not to
# REASON_CHOICES. Changing them to canonical refund spellings silently degrades every ticket
# title to the generic fallback — which is exactly what happened while writing this.
TICKET_REASON_SELECTS = (
    ("services/platform/templates/billing/invoice_detail.html", "invoice_refund_request_reason",
     "services/platform/apps/billing/views.py"),
    ("services/platform/templates/orders/order_detail.html", "refund_request_reason",
     "services/platform/apps/orders/views.py"),
)

_OPTION = re.compile(r'<option value="([^"]*)"')


def _select_options(relative_path: str, select_id: str) -> set[str]:
    html = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    start = html.index(f'id="{select_id}"')
    return {value for value in _OPTION.findall(html[start : html.index("</select>", start)]) if value}


def _reason_titles_keys(relative_path: str) -> set[str]:
    """The literal keys of the ``reason_titles`` map in a ticket-creating view."""
    source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    start = source.index("reason_titles = {")
    body = source[start : source.index("}", start)]
    return set(re.findall(r'"([a-z_]+)":', body))


class RefundReasonVocabularyTests(SimpleTestCase):
    """Forms, model and enum share one vocabulary."""

    def test_every_offered_reason_is_a_valid_choice(self) -> None:
        valid = {value for value, _label in Refund.REASON_CHOICES}
        offending: dict[str, set[str]] = {}

        for template, select_id in REFUND_REASON_SELECTS:
            options = _select_options(template, select_id)
            # Structural-Helper Integrity, per select: a select the scan no longer matches would
            # contribute nothing, and a sum over the rest could still look healthy.
            self.assertTrue(options, msg=f"no <option>s scanned in {template}#{select_id}")
            if unknown := options - valid:
                offending[f"{template}#{select_id}"] = unknown

        self.assertEqual(
            offending,
            {},
            msg=(
                "A refund form offers a reason the Refund record cannot hold. Django accepts it "
                "anyway — objects.create() does not validate choices — so it persists as a value "
                "nothing can filter on. Add the choice or fix the template."
            ),
        )

    def test_ticket_request_selects_still_match_their_own_vocabulary(self) -> None:
        """The look-alike selects answer to a different map, and must keep doing so.

        ``*_refund_request`` opens a support ticket and looks its reason up in a
        ``reason_titles`` dict. Canonicalising those values to the refund vocabulary costs
        every ticket its specific title — a silent downgrade to "Refund Request", with no
        test failing. This pins the two vocabularies apart on purpose.
        """
        for template, select_id, view in TICKET_REASON_SELECTS:
            with self.subTest(template=template):
                self.assertEqual(
                    _select_options(template, select_id) - _reason_titles_keys(view),
                    set(),
                    msg=f"{select_id} offers a reason {view} cannot title; it falls back to the generic one.",
                )

    def test_the_enum_and_the_model_choices_agree(self) -> None:
        """``RefundReason`` is what callers pass; ``REASON_CHOICES`` is what the column holds."""
        self.assertEqual(
            {member.value for member in RefundReason},
            {value for value, _label in Refund.REASON_CHOICES},
        )
