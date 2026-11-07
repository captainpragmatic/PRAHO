"""`{% toggle_badge %}`: a product flag shown as a badge that flips it in place (#821).

Its accessible name is the property ("Active"), which doesn't change when the state does; the state is aria-pressed,
and the badge says it in words. A click posts, and the view returns the same control for the new state, swapped over
the old one. `hx-sync="this:drop"` drops a second click while the first is in flight (the endpoint inverts the flag,
so a replayed click would undo it), and the control is disabled until the answer arrives. A locked control is
disabled, says why, and carries nothing that could post.
"""

import re
from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.products.models import Product
from apps.users.models import User

HTMX = ("hx-post", "hx-target", "hx-swap", "hx-sync", "hx-disabled-elt")


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text.append(data.strip())


def parse(html: str) -> tuple[dict[str, str | None], Parser]:
    parsed = Parser()
    parsed.feed(html)
    buttons = [attrs for tag, attrs in parsed.elements if tag == "button"]
    assert len(buttons) == 1, html
    return buttons[0], parsed


def parse_all(html: str) -> list[tuple[str, dict[str, str | None]]]:
    parsed = Parser()
    parsed.feed(html)
    return parsed.elements


def render(arguments: str, **context: object) -> tuple[dict[str, str | None], Parser]:
    html = Template(
        '{% load i18n ui_components %}{% trans "Active" as label %}{% toggle_badge label ' + arguments + " %}"
    ).render(Context(context))
    return parse(html)


STATES = 'on_text="Active" off_text="Inactive" on_variant="success" off_variant="danger"'


class RenderingTests(SimpleTestCase):
    def test_pressed(self) -> None:
        button, parsed = render(f'pressed=True {STATES} hx_post="/products/p/toggle-active/" html_id="active-p"')
        self.assertEqual(button["aria-pressed"], "true")
        self.assertEqual(button["aria-label"], "Active")
        self.assertEqual(button["id"], "active-p")
        self.assertIn("data-keep-focus", button)  # ui-actions.js gives focus to the swapped-in copy
        self.assertEqual(button["type"], "button")
        self.assertEqual(button["hx-post"], "/products/p/toggle-active/")
        self.assertEqual(button["hx-target"], "this")
        self.assertEqual(button["hx-swap"], "outerHTML")
        self.assertEqual(button["hx-sync"], "this:drop")
        self.assertEqual(button["hx-disabled-elt"], "this")
        self.assertNotIn("disabled", button)
        self.assertEqual(parsed.text, ["Active"])
        badge = next(attrs for tag, attrs in parsed.elements if tag == "span")
        self.assertIn("green", badge["class"] or "")

    def test_unpressed_keeps_the_property_as_its_name_and_says_the_state_in_words(self) -> None:
        button, parsed = render(f'pressed=False {STATES} hx_post="/products/p/toggle-active/"')
        self.assertEqual(button["aria-pressed"], "false")
        self.assertEqual(button["aria-label"], "Active")
        self.assertEqual(parsed.text, ["Inactive"])
        badge = next(attrs for tag, attrs in parsed.elements if tag == "span")
        self.assertIn("red", badge["class"] or "")

    def test_locked_is_disabled_says_why_and_cannot_post(self) -> None:
        button, parsed = render(f"pressed=True {STATES} locked_reason=reason", reason='Admins only: "catalog" <lock>')
        self.assertIn("disabled", button)
        self.assertEqual(button["title"], 'Admins only: "catalog" <lock>')
        self.assertEqual(button["aria-pressed"], "true")
        for name in HTMX:
            self.assertNotIn(name, button)
        self.assertEqual(parsed.text, ["Active"])

    def test_a_tooltip_is_written_only_when_unlocked(self) -> None:
        button, _parsed = render(f'pressed=True {STATES} hx_post="/p/" title="Toggle Active Status"')
        self.assertEqual(button["title"], "Toggle Active Status")

    def test_it_must_either_post_on_this_site_or_be_locked(self) -> None:
        for arguments in (f"pressed=True {STATES}", f'pressed=True {STATES} hx_post="https://evil.example/x"'):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments)


class ToggleViewFragmentTests(TestCase):
    """What the toggle views return is the page's own control for the new state, under the same id."""

    def setUp(self) -> None:
        admin = User.objects.create_user(
            email="toggle-badge@example.com", password="Toggle-pass123!", is_staff=True, is_superuser=True
        )
        self.client.force_login(admin)
        self.product = Product.objects.create(name="Badge product", slug="badge", product_type="shared_hosting")

    def page_control(self, control_id: str) -> str:
        html = self.client.get(reverse("products:product_detail", kwargs={"slug": self.product.slug})).content.decode()
        found = re.search(r'<button[^>]*\bid="' + control_id + r'".*?</button>', html, re.S)
        assert found is not None, f"no #{control_id} on the detail page"
        return found.group(0)

    def toggle(self, field: str, control_id: str) -> str:
        path = reverse(f"products:product_toggle_{field}", kwargs={"slug": self.product.slug})
        response = self.client.post(path, HTTP_HX_REQUEST="true", HTTP_HX_TRIGGER=control_id)
        self.assertEqual(response.status_code, 200)
        return response.content.decode().strip()

    def test_each_fragment_is_the_page_s_control_for_the_new_state(self) -> None:
        for field in ("active", "public", "featured"):
            with self.subTest(field=field):
                control_id = f"detail-{field}-badge"
                before = self.page_control(control_id)
                flipped, _parsed = parse(self.toggle(field, control_id))
                self.product.refresh_from_db()
                state = getattr(self.product, f"is_{field}")
                self.assertEqual(flipped["aria-pressed"], str(state).lower())
                self.assertEqual(flipped["id"], control_id)
                self.assertEqual(self.toggle(field, control_id), before)  # flipped back: byte for byte the page's

    def test_an_id_that_is_not_a_plain_name_is_not_echoed(self) -> None:
        for hostile in ('x" onfocus="evil()', "x y", "a" * 101):
            with self.subTest(hostile=hostile):
                button, _parsed = parse(self.toggle("active", hostile))
                self.assertNotIn("id", button)
                self.assertNotIn("onfocus", button)


class ListPageControlIdTests(TestCase):
    """The list page renders a desktop and a mobile toggle per flag; every id is unique and comes back from the view."""

    def setUp(self) -> None:
        admin = User.objects.create_user(
            email="toggle-ids@example.com", password="Toggle-pass123!", is_staff=True, is_superuser=True
        )
        self.client.force_login(admin)

    def control_ids(self) -> list[str]:
        html = self.client.get(reverse("products:product_list_htmx"), HTTP_HX_REQUEST="true").content.decode()
        return [
            attrs["id"] or ""
            for tag, attrs in parse_all(html)
            if tag == "button" and "id" in attrs and "toggle-" in (attrs.get("hx-post") or "")
        ]

    def test_slugs_that_look_like_a_layout_prefix_get_distinct_ids(self) -> None:
        for slug in ("foo", "m-foo"):
            Product.objects.create(name=slug, slug=slug, product_type="shared_hosting")
        ids = self.control_ids()
        self.assertEqual(len(ids), 8)  # 2 products x (active, public) x (desktop, mobile)
        self.assertEqual(len(set(ids)), 8, ids)

    def test_the_view_echoes_every_id_the_list_page_generates_even_for_the_longest_slug(self) -> None:
        product = Product.objects.create(name="Long", slug="s" * 100, product_type="shared_hosting")
        ids = self.control_ids()
        self.assertEqual(len(ids), 4)
        for control_id in ids:
            with self.subTest(control_id=control_id):
                field = "active" if "-active-" in control_id else "public"
                path = reverse(f"products:product_toggle_{field}", kwargs={"slug": product.slug})
                response = self.client.post(path, HTTP_HX_REQUEST="true", HTTP_HX_TRIGGER=control_id)
                button, _parsed = parse(response.content.decode().strip())
                self.assertEqual(button.get("id"), control_id)
