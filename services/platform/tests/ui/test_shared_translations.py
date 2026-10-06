"""Regression coverage for shared translations and the data-table default."""

from django.conf import settings
from django.core.paginator import Paginator
from django.template import Context, Template
from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils.functional import Promise
from django.utils.translation import override

from apps.ui.templatetags.ui_components import DataTableConfig


class SharedTranslationRenderingTests(SimpleTestCase):
    def test_empty_table_default_follows_the_active_language(self) -> None:
        template = Template("{% load ui_components %}{% data_table headers=headers rows=rows pagination=False %}")
        for language, expected in (("en", "No data available."), ("ro", "Nu există date disponibile.")):
            with self.subTest(language=language), override(language):
                html = template.render(Context({"headers": [], "rows": []}))
                self.assertIn(expected, html)

    def test_default_is_lazy_and_can_be_reused_across_languages(self) -> None:
        config = DataTableConfig()
        self.assertIsInstance(config.empty_message, Promise)
        template = Template("{% load ui_components %}{% data_table headers=headers rows=rows config=config %}")
        for language, expected in (("ro", "Nu există date disponibile."), ("en", "No data available.")):
            with self.subTest(language=language), override(language):
                html = template.render(Context({"headers": [], "rows": [], "config": config}))
                self.assertIn(expected, html)

    def test_compiled_shared_only_duplicate_and_block_messages_render(self) -> None:
        for language, toggle, search, summary in (
            ("ro", "Comută secțiunea", "Căutare", "1\u20131 din 2 rezultate"),
            ("en", "Toggle section", "Search", "1\u20131 of 2 results"),
        ):
            with self.subTest(language=language), override(language):
                section = render_to_string("components/section_card.html", {"sc_title": "Test", "sc_collapsible": True})
                filters = render_to_string("components/list_page_filters.html")
                pagination = render_to_string(
                    "components/pagination.html", {"page_obj": Paginator(range(2), 1).page(1)}
                )
                self.assertIn(f'aria-label="{toggle}"', section)
                self.assertIn(f">{search}</label>", filters)
                self.assertIn(summary, pagination)
                actions = render_to_string("components/form_actions.html")
                self.assertIn("Salvează" if language == "ro" else "Save", actions)

    def test_shared_precedence_preserves_service_owned_copy(self) -> None:
        self.assertEqual(settings.LOCALE_PATHS[0], settings.REPO_ROOT / "shared" / "ui" / "locale")
        for language, search in (("ro", "Căutare"), ("en", "Search")):
            with self.subTest(language=language), override(language):
                html = render_to_string("users/user_list.html", {"users": [], "staff_roles": []})
                self.assertIn(f">{search}\n", html)

    def test_enhanced_table_has_a_correct_romanian_empty_title(self) -> None:
        with override("ro"):
            html = render_to_string(
                "components/table_enhanced.html",
                {"columns": [], "rows": [], "pagination_enabled": False, "include_js": False},
            )
        self.assertIn("Nu s-au găsit date", html)
