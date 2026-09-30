"""Regression tests for invoice_detail.html's refund-request modal and invoices_list.html's
status filter, swapped from raw <button>/<select>/<textarea> elements to
{% button %}/{% input_field %} - Phase 4's TMPL002/003/004 fix for the billing area.

Content, not status: a status-only check would pass even if the swap dropped the exact
attributes the page's own inline JS depends on (type="submit" for the querySelector at
invoice_detail.html:369, name= for FormData.get(), data-modal-target for the open/close JS).

Buttons are found by their visible text via HTMLParser, not by a page-wide substring search -
base.html's own Logout button already has type="submit", so `assertIn('type="submit", content)`
is true on this page regardless of whether THIS swap's button has it. The first version of
this file had exactly that vacuous assertion; caught by mutation-testing it (removing
type="submit" from the swap left every assertion passing) before it shipped.
"""

from __future__ import annotations

import time
from datetime import timedelta
from html.parser import HTMLParser
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.schemas import BillingDocumentPage, Currency, Invoice


def _make_invoice(status: str) -> Invoice:
    currency = Currency(id=1, code="RON", name="Romanian Leu", symbol="lei", decimal_places=2)
    now = timezone.now()
    invoice = Invoice(
        id=1,
        number="INV-2026-0100",
        status=status,
        currency=currency,
        exchange_to_ron=None,
        subtotal_cents=10000,
        tax_cents=2100,
        total_cents=12100,
        issued_at=now,
        due_at=now,
        created_at=now,
        updated_at=now,
        locked_at=None,
        sent_at=None,
        paid_at=now if status == "paid" else None,
    )
    invoice.lines = []
    return invoice


class _ButtonFinder(HTMLParser):
    """Finds every <button>, recording its attributes and visible text, so a test can assert
    on the specific button it means rather than on a substring anywhere on the page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.buttons: list[dict] = []
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "button":
            self.buttons.append({"attrs": dict(attrs), "text": ""})
            self._depth = 1
        elif self.buttons and self._depth:
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "button" and self.buttons:
            self._depth = 0
        elif self.buttons and self._depth:
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self.buttons and self._depth:
            self.buttons[-1]["text"] += data


def _button_with_text(html: str, text: str) -> dict:
    parser = _ButtonFinder()
    parser.feed(html)
    matches = [b for b in parser.buttons if text in b["text"]]
    assert matches, f"no <button> containing {text!r} found; buttons seen: {parser.buttons}"
    assert len(matches) == 1, f"expected exactly one <button> containing {text!r}, found {len(matches)}"
    return matches[0]


class _TagAttrFinder(HTMLParser):
    """Finds every element of one tag name and records its attributes - list_page_filters.html
    hardcodes hx-sync/hx-indicator on its OWN tabs and search input too, so a page-wide
    substring check for "hx-sync=" is satisfied by those and proves nothing about the select
    this test means to check."""

    def __init__(self, tag_name: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tag_name = tag_name
        self.elements: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == self.tag_name:
            self.elements.append(dict(attrs))


def _element_with_name(html: str, tag_name: str, name: str) -> dict:
    parser = _TagAttrFinder(tag_name)
    parser.feed(html)
    matches = [el for el in parser.elements if el.get("name") == name]
    assert matches, f"no <{tag_name} name={name!r}> found; {tag_name}s seen: {parser.elements}"
    assert len(matches) == 1, f"expected exactly one <{tag_name} name={name!r}>, found {len(matches)}"
    return matches[0]


class InvoiceDetailRefundModalTests(TestCase):
    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["session_auth_hash"] = "test-session"
        session["validated_at"] = now.isoformat()
        session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_refund_button_opens_the_modal_by_data_attribute(self, mock_get) -> None:
        mock_get.return_value = _make_invoice("paid")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        self.assertEqual(response.status_code, 200)
        button = _button_with_text(response.content.decode(), "Request Refund")
        self.assertEqual(button["attrs"].get("data-action"), "modal-open")
        self.assertEqual(button["attrs"].get("data-modal-target"), "#invoiceRefundRequestModal")

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_unpaid_invoice_has_no_refund_button(self, mock_get) -> None:
        mock_get.return_value = _make_invoice("issued")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        self.assertNotIn("Request Refund", response.content.decode())

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_submit_button_keeps_type_submit_for_the_inline_js_selector(self, mock_get) -> None:
        """The page's own <script> does `this.querySelector('button[type="submit"]')` to
        disable the button during submission - losing type="submit" on the swap would make
        that selector silently match nothing, and the button would stay clickable forever.
        base.html's own Logout button also has type="submit", so this must check THIS
        specific button, not just that the string appears somewhere on the page."""
        mock_get.return_value = _make_invoice("paid")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        button = _button_with_text(response.content.decode(), "Submit Request")
        self.assertEqual(button["attrs"].get("type"), "submit")

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_cancel_button_closes_the_modal_by_data_attribute(self, mock_get) -> None:
        mock_get.return_value = _make_invoice("paid")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        button = _button_with_text(response.content.decode(), "Cancel")
        self.assertEqual(button["attrs"].get("data-action"), "modal-close")
        self.assertEqual(button["attrs"].get("data-modal-target"), "#invoiceRefundRequestModal")
        self.assertEqual(button["attrs"].get("type"), "button")

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_refund_reason_select_has_the_field_name_the_js_reads(self, mock_get) -> None:
        """The submit handler reads formData.get('refund_reason') - the swap must keep this
        exact name, not the auto-generated id, or the backend would silently receive nothing."""
        mock_get.return_value = _make_invoice("paid")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        content = response.content.decode()
        self.assertIn('name="refund_reason"', content)
        self.assertIn("<select", content)
        self.assertIn(">Service Not Working<", content)

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_refund_notes_textarea_has_the_field_name_the_js_reads(self, mock_get) -> None:
        mock_get.return_value = _make_invoice("paid")

        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))

        content = response.content.decode()
        self.assertIn('name="refund_notes"', content)
        self.assertIn("<textarea", content)
        self.assertIn('rows="4"', content)


class InvoicesListStatusFilterTests(TestCase):
    """invoices/partials/invoice_extra_filters.html's <select>, swapped to
    {% input_field type="select" %}. hx-sync/hx-indicator did not exist on input_field before
    Phase 4 - losing either would let a stale in-flight filter request race a newer one, or
    leave the loading skeleton stuck forever."""

    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["session_auth_hash"] = "test-session"
        session["validated_at"] = now.isoformat()
        session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_status_select_keeps_its_htmx_wiring(self, mock_fetch) -> None:
        """list_page_filters.html hardcodes hx-sync/hx-indicator on its own tabs and search
        input too - this must check the status <select> specifically, or a page-wide substring
        match would pass even if this exact select lost every one of these attributes."""
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"))

        self.assertEqual(response.status_code, 200)
        select = _element_with_name(response.content.decode(), "select", "status")
        self.assertEqual(select.get("hx-get"), reverse("billing:invoices_search_api"))
        self.assertEqual(select.get("hx-target"), "#invoices-content")
        self.assertEqual(select.get("hx-sync"), "closest .list-filters-sync:replace")
        self.assertEqual(select.get("hx-trigger"), "change")
        self.assertEqual(select.get("hx-include"), "#list-filter-search, #list-filter-active-tab")
        self.assertEqual(select.get("hx-indicator"), "#invoices-skeleton")
        self.assertIn("list-filter-extra-select", select.get("class", ""))

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_selected_status_is_marked_selected_on_the_right_option(self, mock_fetch) -> None:
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"), {"status": "paid"})

        content = response.content.decode()
        self.assertIn('<option value="paid" selected>', content)
