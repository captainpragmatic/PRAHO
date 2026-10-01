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
templates were corrected and migration 0048 repairs the stored rows.

The template scan below is the durable part: it is the test that would have caught this on the
day the vocabularies diverged.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from django.test import SimpleTestCase

from apps.billing.refund_models import Refund
from apps.billing.refund_service import RefundReason

REPO_ROOT = Path(__file__).resolve().parents[4]

# The selects whose value actually becomes ``Refund.reason``, identified by element id
# because the *names* do not distinguish them — all five are ``name="refund_reason"``.
REFUND_REASON_SELECTS = (
    ("services/platform/templates/billing/invoice_detail.html", "invoice_refund_reason"),
    ("services/platform/templates/orders/order_detail.html", "refund_reason"),
)

# The portal's refund select also writes a real refund, and is the subtle one: despite being
# called "invoice_refund_request", ``billing:request_refund`` →
# ``InvoiceViewService.request_refund`` → ``api_client.process_refund`` → the platform's
# ``api_process_refund`` → ``RefundService.refund_invoice``.
#
# Its options are not literal <option> tags: the select is a ``{% input_field %}`` fed from a
# view constant, so the vocabulary lives in Python. It is read as source text — the platform
# cannot import portal code — and the template/view wiring is asserted separately, so the scan
# can never quietly check a constant the select no longer renders.
PORTAL_REFUND_TEMPLATE = "services/portal/templates/billing/invoice_detail.html"
PORTAL_REFUND_SELECT_ID = "invoice_refund_request_reason"
PORTAL_REFUND_VIEWS = "services/portal/apps/billing/views.py"
PORTAL_REFUND_CONSTANT = "REFUND_REASON_CHOICES"
PORTAL_REFUND_CONTEXT_KEY = "refund_reason_choices"

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


def _constant_choice_values(relative_path: str, constant: str) -> set[str]:
    """The ``"value"`` entries of a module-level list-of-dicts choices constant, read via ast."""
    tree = ast.parse((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        else:
            continue
        if isinstance(target, ast.Name) and target.id == constant and isinstance(value, ast.List):
            return {
                entry_value.value
                for entry in value.elts
                if isinstance(entry, ast.Dict)
                for key, entry_value in zip(entry.keys, entry.values, strict=True)
                if isinstance(key, ast.Constant)
                and key.value == "value"
                and isinstance(entry_value, ast.Constant)
                and entry_value.value
            }
    raise AssertionError(f"{relative_path} has no list constant named {constant}")


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
        scanned = 0

        for template, select_id in REFUND_REASON_SELECTS:
            options = _select_options(template, select_id)
            scanned += len(options)
            if unknown := options - valid:
                offending[f"{template}#{select_id}"] = unknown

        portal_options = _constant_choice_values(PORTAL_REFUND_VIEWS, PORTAL_REFUND_CONSTANT)
        scanned += len(portal_options)
        if unknown := portal_options - valid:
            offending[f"{PORTAL_REFUND_VIEWS}#{PORTAL_REFUND_CONSTANT}"] = unknown

        self.assertEqual(
            offending,
            {},
            msg=(
                "A refund form offers a reason the Refund record cannot hold. Django accepts it "
                "anyway — objects.create() does not validate choices — so it persists as a value "
                "nothing can filter on. Add the choice or fix the template."
            ),
        )
        # Structural-Helper Integrity: a scan that matched nothing must fail, not pass.
        self.assertGreaterEqual(scanned, 25)
        # Canary: the portal's select is the one missed on the first pass over this bug, because
        # it lives in the other service.
        self.assertTrue(portal_options)

    def test_portal_refund_select_renders_the_scanned_constant(self) -> None:
        """The scan above reads the portal's vocabulary from a Python constant. That proves
        nothing unless the refund <select> is actually rendered from it: the template must feed
        the select from the context key, and the view must bind that key to the constant."""
        template = (REPO_ROOT / PORTAL_REFUND_TEMPLATE).read_text(encoding="utf-8")
        select_tag = next(
            (line for line in template.splitlines() if f'html_id="{PORTAL_REFUND_SELECT_ID}"' in line),
            "",
        )
        self.assertIn("{% input_field", select_tag, msg="the portal refund select is no longer an input_field")
        self.assertIn(f"options={PORTAL_REFUND_CONTEXT_KEY}", select_tag)

        views = (REPO_ROOT / PORTAL_REFUND_VIEWS).read_text(encoding="utf-8")
        self.assertIn(f'"{PORTAL_REFUND_CONTEXT_KEY}": {PORTAL_REFUND_CONSTANT}', views)

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

    def test_the_backfill_only_rewrites_values_that_were_never_valid(self) -> None:
        """Migration 0048 must repair bad rows without touching correct ones.

        The mapping is one-way by construction: every key is a spelling the column should
        never have held, and every target is a real choice. If a key were also a valid
        choice the migration would be rewriting good data.
        """
        import importlib  # noqa: PLC0415

        migration = importlib.import_module("apps.billing.migrations.0048_alter_refund_reason")
        valid = {value for value, _label in Refund.REASON_CHOICES}

        self.assertTrue(migration.REASON_ALIASES, msg="The alias map is empty; the backfill does nothing.")
        for stored, canonical in migration.REASON_ALIASES.items():
            with self.subTest(stored=stored):
                self.assertNotIn(stored, valid, msg=f"{stored!r} is a valid choice — the backfill would corrupt it.")
                self.assertIn(canonical, valid, msg=f"{stored!r} maps to {canonical!r}, which is not a valid choice.")

    def test_the_spellings_the_templates_used_to_offer_are_all_covered(self) -> None:
        """Fix Completeness: each corrected template value needs a backfill entry, or the rows
        already written under it stay unreadable forever."""
        import importlib  # noqa: PLC0415

        migration = importlib.import_module("apps.billing.migrations.0048_alter_refund_reason")

        for retired in ("dispute_resolution", "duplicate_invoice", "duplicate_order", "cancellation_request"):
            self.assertIn(retired, migration.REASON_ALIASES)
