"""Regression guard for #285: domain_renew.html must be real markup, not escaped text.

The file was corrupted by ace3ddfa so that everything from ~line 120 to EOF
collapsed onto one physical line with literal ``\n`` / ``\"`` escape sequences
instead of real newlines and quotes. That broke the rendered markup and the
inline renewal-summary calculator. These tests fail on that corruption and on
any future re-introduction of it.
"""

from pathlib import Path

from django.template import engines
from django.test import SimpleTestCase

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2] / "templates/domains/domain_renew.html"
)


class DomainRenewTemplateTests(SimpleTestCase):
    """#285: template source is well-formed markup, not escaped text."""

    def test_source_has_no_literal_escape_sequences(self) -> None:
        """The file must contain no literal backslash-n / backslash-quote."""
        content = TEMPLATE_PATH.read_text()
        self.assertNotIn(
            "\\n",
            content,
            "domain_renew.html contains literal \\n — the file is corrupted (#285)",
        )
        self.assertNotIn(
            '\\"',
            content,
            'domain_renew.html contains literal \\" — the file is corrupted (#285)',
        )

    def test_renewal_summary_script_is_real_markup(self) -> None:
        """The inline calculator must be present as markup with an intact JS literal."""
        content = TEMPLATE_PATH.read_text()
        # These only exist as real markup once the escape corruption is undone.
        self.assertIn('<script nonce="{{ csp_nonce }}">', content)
        self.assertIn("function updateSummary()", content)
        self.assertIn("summaryDiv.innerHTML = `", content)  # JS template literal

    def test_template_compiles(self) -> None:
        """Django must be able to parse the template (balanced tags/blocks)."""
        # get_template loads and compiles the template; a corrupted or unbalanced
        # file raises TemplateSyntaxError here before any rendering.
        template = engines["django"].get_template("domains/domain_renew.html")
        self.assertTrue(template.template.nodelist)
