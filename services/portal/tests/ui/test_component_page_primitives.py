"""
Page Shell Primitives Tests — Phase C.2

Tests for page_header (block tag), section_card (block tag), stat_tile, and
empty_state inclusion tags in apps.ui.templatetags.ui_components.

page_header and section_card load child templates via context.template.engine,
so the render helper must bind the template to the context.  No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from django.template import Context, Template
from django.test import SimpleTestCase

# ===============================================================================
# RENDER HELPERS
# ===============================================================================


def _render_inclusion(template_str: str, context: dict | None = None) -> str:
    """
    Render an inclusion_tag template string.

    Standard inclusion tags (stat_tile, empty_state) do NOT need context.template
    because they look up the included template at registration time, not at render.
    """
    t = Template("{% load ui_components %}" + template_str)
    return t.render(Context(context or {}))


def _render_block(template_str: str, context: dict | None = None) -> str:
    """
    Render a block-tag template string with context.template properly bound.

    page_header and section_card resolve the component template at render time
    via ``context.template.engine.get_template()``. Binding the template ensures
    context.template is not None.
    """
    t = Template("{% load ui_components %}" + template_str)
    ctx = Context(context or {})
    ctx.render_context.push()
    try:
        with ctx.bind_template(t):
            return t._render(ctx)
    finally:
        ctx.render_context.pop()


# ===============================================================================
# page_header TESTS
# ===============================================================================


class PageHeaderTagTests(SimpleTestCase):
    """Tests for the {% page_header %}...{% end_page_header %} block tag."""

    def test_title_appears_in_h1(self) -> None:
        result = _render_block(
            '{% page_header title="Invoices" %}{% end_page_header %}'
        )
        self.assertIn("<h1", result)
        self.assertIn("Invoices", result)

    def test_subtitle_appears(self) -> None:
        result = _render_block(
            '{% page_header title="Orders" subtitle="Your order history" %}{% end_page_header %}'
        )
        self.assertIn("Your order history", result)

    def test_no_subtitle_if_not_supplied(self) -> None:
        result = _render_block(
            '{% page_header title="Dashboard" %}{% end_page_header %}'
        )
        # The subtitle <p> must not appear if subtitle is omitted
        self.assertNotIn("text-slate-400", result.split("Invoices")[0])

    def test_icon_produces_svg(self) -> None:
        result = _render_block(
            '{% page_header title="Billing" icon="invoices" %}{% end_page_header %}'
        )
        self.assertIn("<svg", result)

    def test_no_icon_means_no_svg_in_header(self) -> None:
        result = _render_block(
            '{% page_header title="Simple" %}{% end_page_header %}'
        )
        # Without an icon, no SVG in the header section
        self.assertNotIn("<svg", result)

    def test_actions_slot_rendered(self) -> None:
        result = _render_block(
            '{% page_header title="Services" %}'
            '<button id="add-btn">Add service</button>'
            '{% end_page_header %}'
        )
        self.assertIn("Add service", result)
        self.assertIn('id="add-btn"', result)

    def test_empty_actions_slot_omits_actions_div(self) -> None:
        result = _render_block(
            '{% page_header title="Overview" %}{% end_page_header %}'
        )
        # No actions wrapper div when slot is empty
        self.assertNotIn("sm:ml-16", result)

    def test_custom_css_class_applied(self) -> None:
        result = _render_block(
            '{% page_header title="Custom" css_class="mb-8" %}{% end_page_header %}'
        )
        self.assertIn("mb-8", result)

    def test_variable_title_interpolated(self) -> None:
        result = _render_block(
            "{% page_header title=page_title %}{% end_page_header %}",
            {"page_title": "My Title From Var"},
        )
        self.assertIn("My Title From Var", result)

    def test_title_html_escaped(self) -> None:
        result = _render_block(
            "{% page_header title=page_title %}{% end_page_header %}",
            {"page_title": "<script>xss</script>"},
        )
        self.assertNotIn("<script>", result)


# ===============================================================================
# section_card TESTS
# ===============================================================================


class SectionCardTagTests(SimpleTestCase):
    """Tests for the {% section_card %}...{% end_section_card %} block tag."""

    def test_title_appears_in_h3(self) -> None:
        result = _render_block(
            '{% section_card title="Customer Details" %}{% end_section_card %}'
        )
        self.assertIn("<h3", result)
        self.assertIn("Customer Details", result)

    def test_content_slot_rendered(self) -> None:
        result = _render_block(
            '{% section_card title="Info" %}'
            '<p id="inner">My card content</p>'
            '{% end_section_card %}'
        )
        self.assertIn("My card content", result)
        self.assertIn('id="inner"', result)

    def test_icon_produces_svg(self) -> None:
        result = _render_block(
            '{% section_card title="Profile" icon="user" %}{% end_section_card %}'
        )
        self.assertIn("<svg", result)

    def test_no_title_means_no_h3(self) -> None:
        result = _render_block(
            '{% section_card %}some content{% end_section_card %}'
        )
        self.assertNotIn("<h3", result)

    def test_collapsible_adds_alpine_directive(self) -> None:
        result = _render_block(
            '{% section_card title="Collapsible" collapsible=True %}{% end_section_card %}'
        )
        self.assertIn("x-data", result)

    def test_html_id_attribute_rendered(self) -> None:
        result = _render_block(
            '{% section_card title="Section" html_id="details-card" %}{% end_section_card %}'
        )
        self.assertIn('id="details-card"', result)

    def test_custom_css_class(self) -> None:
        result = _render_block(
            '{% section_card title="Custom" css_class="mt-6" %}{% end_section_card %}'
        )
        self.assertIn("mt-6", result)

    def test_default_padding_applied(self) -> None:
        """Default padding should be p-6."""
        result = _render_block(
            '{% section_card title="Padded" %}{% end_section_card %}'
        )
        self.assertIn("p-6", result)

    def test_custom_padding_overrides_default(self) -> None:
        result = _render_block(
            '{% section_card title="Compact" padding="p-4 sm:p-6" %}{% end_section_card %}'
        )
        self.assertIn("p-4", result)


# ===============================================================================
# stat_tile TESTS
# ===============================================================================


class StatTileTagTests(SimpleTestCase):
    """Tests for the {% stat_tile %} inclusion tag."""

    def test_label_rendered(self) -> None:
        result = _render_inclusion('{% stat_tile "Total Revenue" "€1,250" %}')
        self.assertIn("Total Revenue", result)

    def test_value_rendered(self) -> None:
        result = _render_inclusion('{% stat_tile "Orders" "42" %}')
        self.assertIn("42", result)

    def test_icon_renders_svg(self) -> None:
        result = _render_inclusion('{% stat_tile "Active" "3" icon="check" %}')
        self.assertIn("<svg", result)

    def test_no_icon_no_svg(self) -> None:
        result = _render_inclusion('{% stat_tile "Label" "Value" %}')
        self.assertNotIn("<svg", result)

    def test_meta_rendered(self) -> None:
        result = _render_inclusion('{% stat_tile "Revenue" "€500" meta="Last 30 days" %}')
        self.assertIn("Last 30 days", result)

    def test_no_meta_if_not_supplied(self) -> None:
        result = _render_inclusion('{% stat_tile "Label" "Value" %}')
        # meta paragraph must not appear
        self.assertNotIn("text-xs text-slate-500", result)

    def test_success_variant_uses_green_classes(self) -> None:
        result = _render_inclusion('{% stat_tile "OK" "1" icon="check" variant="success" %}')
        self.assertIn("bg-green-900", result)

    def test_warning_variant_uses_yellow_classes(self) -> None:
        result = _render_inclusion('{% stat_tile "Warn" "1" icon="warning" variant="warning" %}')
        self.assertIn("bg-yellow-900", result)

    def test_danger_variant_uses_red_classes(self) -> None:
        result = _render_inclusion('{% stat_tile "Err" "1" icon="ban" variant="danger" %}')
        self.assertIn("bg-red-900", result)

    def test_primary_variant_uses_blue_classes(self) -> None:
        result = _render_inclusion('{% stat_tile "Info" "1" icon="info" variant="primary" %}')
        self.assertIn("bg-blue-900", result)

    def test_positive_trend_uses_green(self) -> None:
        result = _render_inclusion('{% stat_tile "Revenue" "€500" trend="+12%" %}')
        self.assertIn("text-green-400", result)

    def test_negative_trend_uses_red(self) -> None:
        result = _render_inclusion('{% stat_tile "Churn" "5%" trend="-3%" %}')
        self.assertIn("text-red-400", result)

    def test_custom_css_class(self) -> None:
        result = _render_inclusion('{% stat_tile "Label" "Val" css_class="col-span-2" %}')
        self.assertIn("col-span-2", result)


# ===============================================================================
# empty_state TESTS
# ===============================================================================


class EmptyStateTagTests(SimpleTestCase):
    """Tests for the {% empty_state %} inclusion tag."""

    def test_title_rendered(self) -> None:
        result = _render_inclusion('{% empty_state title="No invoices found" %}')
        self.assertIn("No invoices found", result)

    def test_body_rendered(self) -> None:
        result = _render_inclusion(
            '{% empty_state title="Empty" body="Create your first item to get started." %}'
        )
        self.assertIn("Create your first item to get started.", result)

    def test_no_body_if_not_supplied(self) -> None:
        result = _render_inclusion('{% empty_state title="Empty" %}')
        self.assertNotIn("max-w-sm", result)

    def test_icon_renders_svg(self) -> None:
        result = _render_inclusion('{% empty_state title="Empty" icon="folder" %}')
        self.assertIn("<svg", result)

    def test_action_link_rendered(self) -> None:
        result = _render_inclusion(
            '{% empty_state title="None" action_url="/create/" action_text="Create" %}'
        )
        self.assertIn('href="/create/"', result)
        self.assertIn("Create", result)

    def test_no_action_if_url_missing(self) -> None:
        result = _render_inclusion('{% empty_state title="None" action_text="Create" %}')
        self.assertNotIn("<a ", result)

    def test_no_action_if_text_missing(self) -> None:
        result = _render_inclusion('{% empty_state title="None" action_url="/create/" %}')
        self.assertNotIn("<a ", result)

    def test_custom_css_class(self) -> None:
        result = _render_inclusion('{% empty_state title="None" css_class="py-24" %}')
        self.assertIn("py-24", result)
