"""Every action on the staff customer page is drawn by the button component, in one size per row.

The header's status buttons sat beside Edit Customer in another size and shape, and the member card's
Suspend, Activate, Remove and Cannot Remove each had hand-written classes, because the component could
not carry confirmation text or a tooltip. These tests render the real page and read what the browser gets.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

TEMPLATE = Path(settings.BASE_DIR) / "templates" / "customers" / "detail.html"
MD = {"px-4", "py-2", "text-sm"}
XS = {"px-2", "py-1", "text-xs"}
WARNING, DANGER, SUCCESS, SECONDARY = "bg-yellow-500", "bg-red-600", "bg-green-700", "bg-slate-600"


class Controls(HTMLParser):
    """Each <a> and <button> with its attributes and visible text."""

    def __init__(self) -> None:
        super().__init__()
        self.items: list[dict[str, str]] = []
        self._open: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("a", "button"):
            item = {name: value or "" for name, value in attrs}
            item["_tag"], item["_text"] = tag, ""
            self.items.append(item)
            self._open.append(item)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("a", "button") and self._open:
            self._open.pop()

    def handle_data(self, data: str) -> None:
        for item in self._open:
            item["_text"] += data

    def one(self, **wanted: str) -> dict[str, str]:
        found = [i for i in self.items if all(i.get(k) == v for k, v in wanted.items())]
        assert len(found) == 1, (wanted, len(found))
        return found[0]

    def labelled(self, text: str) -> list[dict[str, str]]:
        return [i for i in self.items if " ".join(i["_text"].split()) == text]


def classes(item: dict[str, str]) -> set[str]:
    return set(item.get("class", "").split())


class CustomerPageButtonTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(email="admin-staff@example.test", password="x", is_staff=True)
        User.objects.filter(pk=self.staff.pk).update(staff_role="admin")
        self.client.force_login(self.staff)
        self.customer = Customer.objects.create(
            name="Buttons SRL", customer_type="company", primary_email="b@example.test"
        )
        self.owner = User.objects.create_user(email="owner@example.test", password="x")
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner", is_active=True)

    def _page(self, status: str) -> Controls:
        Customer.objects.filter(pk=self.customer.pk).update(status=status)
        self.assertEqual(Customer.objects.get(pk=self.customer.pk).status, status)
        response = self.client.get(reverse("customers:detail", args=[self.customer.pk]))
        self.assertEqual(response.status_code, 200)
        parsed = Controls()
        parsed.feed(response.content.decode())
        return parsed

    def _assert_confirms(self, item: dict[str, str], form_id: str) -> None:
        self.assertEqual(item.get("data-action"), "confirm-dangerous")
        self.assertEqual(item.get("data-submit-form"), form_id)
        for name in ("data-title", "data-message", "data-confirm-text"):
            self.assertTrue(item.get(name), name)
            self.assertNotIn("&", item[name], f"{name} shows escaped entities")

    def test_status_buttons_match_edit_customer(self) -> None:
        cases = {
            "prospect": ["activate"],
            "active": ["deactivate", "suspend"],
            "inactive": ["reactivate", "suspend"],
            "suspended": ["unsuspend"],
        }
        for status, actions in cases.items():
            with self.subTest(status=status):
                page = self._page(status)
                edit = page.one(href=reverse("customers:edit", args=[self.customer.pk]))
                self.assertIn("ui-btn", classes(edit))
                self.assertLessEqual(MD, classes(edit))
                for action in actions:
                    button = page.one(**{"data-submit-form": f"status-form-{action}"})
                    self.assertIn("ui-btn", classes(button))
                    self.assertLessEqual(MD, classes(button), action)
                    variant = WARNING if action in ("suspend", "deactivate") else SECONDARY
                    self.assertIn(variant, classes(button), action)
                    self._assert_confirms(button, f"status-form-{action}")

    def test_member_card_controls_share_one_size(self) -> None:
        page = self._page("active")
        sign_in = page.one(href=reverse("customers:customer_view_start", args=[self.customer.pk, self.owner.pk]))
        suspend = page.one(**{"data-submit-form": f"suspend-form-{self.owner.pk}"})
        [cannot_remove] = page.labelled("Cannot Remove")
        self.assertIn(WARNING, classes(suspend))
        self._assert_confirms(suspend, f"suspend-form-{self.owner.pk}")
        self.assertIn("disabled", cannot_remove)
        self.assertTrue(cannot_remove.get("title"))
        for item in (sign_in, suspend, cannot_remove):
            self.assertIn("ui-btn", classes(item))
            self.assertLessEqual(XS, classes(item), item["_text"].strip())

    def test_sign_in_as_customer_opens_its_own_tab(self) -> None:
        page = self._page("prospect")
        sign_in = page.one(href=reverse("customers:customer_view_start", args=[self.customer.pk, self.owner.pk]))
        self.assertEqual(sign_in.get("target"), "_blank")
        self.assertEqual(sign_in.get("rel"), "noopener")

    def test_remove_and_reactivate_a_member(self) -> None:
        second = User.objects.create_user(email="second@example.test", password="x", is_active=False)
        membership = CustomerMembership.objects.create(
            user=second, customer=self.customer, role="viewer", is_active=True
        )
        page = self._page("active")
        remove = page.one(**{"data-submit-form": f"remove-form-{membership.pk}"})
        activate = page.one(**{"data-submit-form": f"activate-form-{second.pk}"})
        self.assertIn(DANGER, classes(remove))
        self.assertIn(SUCCESS, classes(activate))
        for item, form in ((remove, f"remove-form-{membership.pk}"), (activate, f"activate-form-{second.pk}")):
            self.assertIn("ui-btn", classes(item))
            self.assertLessEqual(XS, classes(item))
            self._assert_confirms(item, form)

    def test_no_hand_written_button_remains_for_want_of_component_arguments(self) -> None:
        source = TEMPLATE.read_text()
        exemptions = re.findall(r"tmpl-allow TMPL002: (.*?)#\}", source)
        self.assertEqual([e for e in exemptions if "attrs takes one literal string" in e], [])
        # The rest are a drop-down's menu entries, its Alpine toggle and an icon-only copy control.
        self.assertEqual(len(exemptions), 6)
