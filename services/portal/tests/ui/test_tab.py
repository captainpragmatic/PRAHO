"""`{% tablist %}`, `{% tab %}` and `{% tab_panel_attrs %}`: real tabs and filter groups (#821).

Real tabs (kind="tab") are a tablist of role="tab" buttons, each joined to its role="tabpanel" by id, with a roving
tabindex; one registered Alpine component, `tabs`, owns the selection. A filter (kind="filter") is a labelled group
of aria-pressed buttons and is never a tablist: its state belongs to whatever already holds the filter value.
"""

from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase
from django.utils.safestring import mark_safe

HOSTILE = 'x" onclick="evil()'


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text.append(data.strip())

    def with_attr(self, name: str, value: str | None = None) -> list[dict[str, str | None]]:
        return [dict(a) for _t, a in self.elements if name in dict(a) and (value is None or dict(a)[name] == value)]


def render(body: str, **context: object) -> Parser:
    html = Template("{% load i18n ui_components %}" + body).render(Context(context))
    parsed = Parser()
    parsed.feed(html)
    return parsed


def tablist(*tabs: str, opening: str = 'label="Sections" group="account"') -> str:
    return "{% tablist " + opening + " %}" + "".join(tabs) + "{% end_tablist %}"


OVERVIEW = '{% tab "overview" "Overview" selected=True active_class="on now" inactive_class="off" class="base" %}'
BACKUPS = '{% tab "backups" "Backups" active_class="on now" inactive_class="off" class="base" %}'
PANELS = '<div {% tab_panel_attrs "overview" group="account" selected=True %}></div><div {% tab_panel_attrs "backups" group="account" %}></div>'


class RealTabTests(SimpleTestCase):
    def test_the_tablist_is_named(self) -> None:
        parsed = render(tablist(OVERVIEW, BACKUPS, opening='label="Sections" group="account" class="flex gap-2"'))
        lists = parsed.with_attr("role", "tablist")
        self.assertEqual(len(lists), 1)
        self.assertEqual(lists[0]["aria-label"], "Sections")
        self.assertEqual(lists[0]["class"], "flex gap-2")

    def test_each_tab_is_joined_to_its_panel_by_id(self) -> None:
        parsed = render(tablist(OVERVIEW, BACKUPS) + PANELS)
        tabs = parsed.with_attr("role", "tab")
        panels = parsed.with_attr("role", "tabpanel")
        self.assertEqual([t["id"] for t in tabs], ["account-tab-overview", "account-tab-backups"])
        self.assertEqual([p["id"] for p in panels], ["account-panel-overview", "account-panel-backups"])
        self.assertEqual([t["aria-controls"] for t in tabs], [p["id"] for p in panels])
        self.assertEqual([p["aria-labelledby"] for p in panels], [t["id"] for t in tabs])
        self.assertEqual([p["tabindex"] for p in panels], ["0", "0"])

    def test_the_server_renders_the_selection_with_a_roving_tabindex(self) -> None:
        tabs = render(tablist(OVERVIEW, BACKUPS)).with_attr("role", "tab")
        self.assertEqual([t["aria-selected"] for t in tabs], ["true", "false"])
        self.assertEqual([t["tabindex"] for t in tabs], ["0", "-1"])
        self.assertEqual([t["type"] for t in tabs], ["button", "button"])

    def test_the_tabs_component_owns_the_state_through_data_not_spliced_values(self) -> None:
        tab = render(tablist(OVERVIEW)).with_attr("role", "tab")[0]
        self.assertEqual(tab["data-tab"], "overview")
        self.assertEqual(tab["data-active-class"], "on now")
        self.assertEqual(tab["data-inactive-class"], "off")
        self.assertEqual(tab["@click"], "select($el)")
        self.assertEqual(tab["@keydown"], "onKeydown($event)")
        self.assertEqual(tab[":aria-selected"], "isSelected($el)")
        self.assertEqual(tab[":tabindex"], "tabIndex($el)")
        self.assertEqual(tab[":class"], "tabClass($el)")
        self.assertEqual((tab["class"] or "").split()[-1], "base")
        self.assertNotIn("on", (tab["class"] or "").split())

    def test_a_panel_is_shown_by_the_component_and_only_the_first_paint_differs(self) -> None:
        panels = render(tablist(OVERVIEW, BACKUPS) + PANELS).with_attr("role", "tabpanel")
        self.assertEqual([p["x-show"] for p in panels], ["isPanel($el)", "isPanel($el)"])
        self.assertEqual([p["data-tab-panel"] for p in panels], ["overview", "backups"])
        self.assertNotIn("x-cloak", panels[0])
        self.assertIn("x-cloak", panels[1])

    def test_no_control_repeats_an_attribute(self) -> None:
        for _tag, attrs in render(tablist(OVERVIEW, BACKUPS) + PANELS).elements:
            names = [name for name, _value in attrs]
            self.assertEqual(len(names), len(set(names)), attrs)

    def test_icon_count_and_badge_join_the_label(self) -> None:
        parsed = render(tablist('{% tab "jobs" "Jobs" icon="settings" count=jobs selected=True %}'), jobs=0)
        self.assertEqual(parsed.text, ["Jobs (0)"])
        self.assertEqual(len([tag for tag, _attrs in parsed.elements if tag == "svg"]), 1)
        no_count = render(tablist('{% tab "jobs" "Jobs" selected=True %}'))
        self.assertEqual(no_count.text, ["Jobs"])

    def test_values_are_escaped_even_when_marked_safe(self) -> None:
        safe = mark_safe(HOSTILE)  # noqa: S308
        parsed = render(
            tablist(
                '{% tab "a" hostile selected=True class=hostile active_class=hostile inactive_class=hostile %}',
                opening='label=hostile group="g" class=hostile',
            ),
            hostile=safe,
        )
        for _tag, attrs in parsed.elements:
            self.assertNotIn("onclick", dict(attrs))
        tab = parsed.with_attr("role", "tab")[0]
        self.assertEqual(tab["data-active-class"], HOSTILE)
        self.assertEqual(parsed.with_attr("role", "tablist")[0]["aria-label"], HOSTILE)
        self.assertEqual(parsed.text, [HOSTILE])


class FilterTests(SimpleTestCase):
    FILTER = 'label="Status" kind="filter" class="flex"'

    def test_a_filter_is_a_labelled_group_never_a_tablist(self) -> None:
        parsed = render(
            tablist(
                '{% tab "" "All" selected=True data_action="filter-tab" data_select_name="status" %}',
                opening=self.FILTER,
            )
        )
        self.assertEqual(parsed.with_attr("role", "group")[0]["aria-label"], "Status")
        self.assertEqual(parsed.with_attr("role", "tablist"), [])
        self.assertEqual(parsed.with_attr("role", "tab"), [])

    def test_the_server_renders_pressed_and_its_classes_for_the_action_that_owns_the_value(self) -> None:
        parsed = render(
            tablist(
                '{% tab "" "All" selected=True active_class="on" inactive_class="off" class="base" '
                'data_action="filter-tab" data_select_name="status" data_select_value="" %}',
                '{% tab "active" "Active" active_class="on" inactive_class="off" class="base" '
                'data_action="filter-tab" data_select_name="status" data_select_value="active" %}',
                opening=self.FILTER,
            )
        )
        buttons = parsed.with_attr("aria-pressed")
        self.assertEqual([b["aria-pressed"] for b in buttons], ["true", "false"])
        self.assertEqual([b["data-select-value"] for b in buttons], ["", "active"])
        self.assertEqual([b["data-action"] for b in buttons], ["filter-tab", "filter-tab"])
        self.assertEqual(buttons[0]["data-active-class"], "on")
        self.assertEqual(buttons[0]["data-inactive-class"], "off")
        self.assertIn("on", (buttons[0]["class"] or "").split())
        self.assertIn("off", (buttons[1]["class"] or "").split())

    def test_a_filter_can_be_driven_by_the_alpine_component_that_owns_it(self) -> None:
        parsed = render(
            tablist(
                '{% tab "monthly" "Monthly" selected=True class="base" alpine_click="billingPeriod = \'monthly\'" '
                "alpine_pressed=\"isPeriod('monthly')\" alpine_class=\"tabClass('monthly')\" %}",
                opening=self.FILTER,
            )
        )
        button = parsed.with_attr("aria-pressed")[0]
        self.assertEqual(button["aria-pressed"], "true")
        self.assertEqual(button["@click"], "billingPeriod = 'monthly'")
        self.assertEqual(button[":aria-pressed"], "isPeriod('monthly')")
        self.assertEqual(button[":class"], "tabClass('monthly')")
        self.assertNotIn("data-tab", button)

    def test_a_badge_sits_beside_the_label(self) -> None:
        parsed = render(
            tablist(
                '{% tab "annual" "Annual" badge="Save 20%" class="base" alpine_click="a = 1" alpine_pressed="b" %}',
                opening=self.FILTER,
            )
        )
        self.assertEqual(parsed.text, ["Annual", "Save 20%"])


class RefusalTests(SimpleTestCase):
    def test_misuse_is_refused(self) -> None:
        for body in (
            '{% tab "a" "A" %}',
            tablist('{% tab "bad name" "A" %}'),
            tablist('{% tab "" "A" %}'),
            tablist('{% tab "a" "" %}'),
            tablist('{% tab "a" "A" icon="no-such-icon" %}'),
            tablist('{% tab "a" "A" unknown=1 %}'),
            tablist('{% tab "a" "A" alpine_click="x = 1" %}'),
            tablist('{% tab "a" "A" data_action="filter-tab" %}'),
            tablist('{% tab "a" "A" %}', opening='label="" group="g"'),
            tablist('{% tab "a" "A" %}', opening='label="L"'),
            tablist('{% tab "a" "A" %}', opening='label="L" group="bad id"'),
            tablist('{% tab "a" "A" %}', opening='label="L" group="g" kind="other"'),
            tablist('{% tab "a" "A" %}', opening='label="L" kind="filter"'),
            '<div {% tab_panel_attrs "bad name" group="g" %}>',
            '<div {% tab_panel_attrs "a" group="bad id" %}>',
        ):
            with self.subTest(body=body), self.assertRaises(TemplateSyntaxError):
                render(body)
