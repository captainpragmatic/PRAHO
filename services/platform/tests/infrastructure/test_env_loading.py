"""
Tests for .env loading in settings files.

Verifies that dev settings load dotenv while prod/staging do not,
that the credential vault master key is available in test settings,
and that the comment-polluted-value guard (#364) works.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import TestCase
from dotenv import dotenv_values

# Settings directory: services/platform/config/settings/
_SETTINGS_DIR = Path(__file__).resolve().parents[2] / "config" / "settings"

# Repo root holds the .env.example.* templates.
_REPO_ROOT = Path(__file__).resolve().parents[4]

# An empty-value var followed by an inline comment: KEY=   # note. dotenv 1.x keeps the comment
# text as the VALUE for these (#364), so the templates must never ship this pattern. Also catch
# the leading-whitespace and `export KEY=` variants — dotenv leaks the comment for those too, so
# the hygiene guardrail must reject them in future edits even though the current templates use
# neither.
_EMPTY_VALUE_INLINE_COMMENT = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=[ \t]*#")


class TestEnvLoading(TestCase):
    """Tests for .env loading configuration across settings files."""

    def test_dev_settings_has_load_dotenv(self) -> None:
        """Dev settings file contains load_dotenv call."""
        dev_py = _SETTINGS_DIR / "dev.py"
        content = dev_py.read_text()

        self.assertIn("load_dotenv", content)

    def test_prod_settings_does_not_load_dotenv(self) -> None:
        """Prod settings must NOT load .env (secrets come from deployment platform)."""
        prod_py = _SETTINGS_DIR / "prod.py"
        content = prod_py.read_text()

        self.assertNotIn("load_dotenv", content)

    def test_staging_settings_does_not_load_dotenv(self) -> None:
        """Staging settings must NOT load .env."""
        staging_py = _SETTINGS_DIR / "staging.py"
        content = staging_py.read_text()

        self.assertNotIn("load_dotenv", content)

    def test_credential_vault_master_key_available(self) -> None:
        """Test settings have CREDENTIAL_VAULT_MASTER_KEY set."""
        key = getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None)

        self.assertTrue(key, "CREDENTIAL_VAULT_MASTER_KEY must be set in test settings")


class TestDotenvEmptyValueCommentQuirk(TestCase):
    """#364: characterize the python-dotenv behavior the guard defends against.

    dotenv strips an inline `# comment` for a NON-empty value, but keeps it as the VALUE when the
    value is empty. This test locks that behavior in place — if a future dotenv release fixes the
    quirk, it will fail loudly and signal that the runtime guard can be removed.
    """

    def _parse(self, body: str) -> dict[str, str | None]:
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(body)
            path = fh.name
        try:
            return dotenv_values(path)
        finally:
            os.unlink(path)

    def test_empty_value_with_inline_comment_leaks_the_comment(self) -> None:
        parsed = self._parse("KEY=   # some note\n")

        # The bug: the comment text becomes the value instead of an empty string.
        self.assertEqual(parsed["KEY"], "# some note")

    def test_non_empty_value_strips_its_inline_comment(self) -> None:
        parsed = self._parse("KEY=realvalue   # trailing\n")

        self.assertEqual(parsed["KEY"], "realvalue")

    def test_quoted_empty_value_stays_empty(self) -> None:
        parsed = self._parse('KEY=""   # note\n')

        self.assertEqual(parsed["KEY"], "")


class TestCommentPollutedEnvGuard(TestCase):
    """#364: the load-time guard must unset comment-polluted vars without touching real env."""

    def setUp(self) -> None:
        # Import here so a settings-import failure surfaces as a test error, not a collection error.
        from config.settings.dev import _strip_comment_polluted_env  # noqa: PLC0415

        self._guard = _strip_comment_polluted_env

    def _env_file(self, body: str) -> str:
        fd, name = tempfile.mkstemp(suffix=".env")
        os.close(fd)
        Path(name).write_text(body)
        self.addCleanup(os.unlink, name)
        return name

    def test_removes_comment_polluted_var(self) -> None:
        path = self._env_file("DJANGO_ENCRYPTION_KEY=   # AES key note\n")
        # Simulate what load_dotenv (override=False) would have injected.
        with mock.patch.dict(os.environ, {"DJANGO_ENCRYPTION_KEY": "# AES key note"}, clear=False):
            removed = self._guard(Path(path))

            self.assertEqual(removed, ["DJANGO_ENCRYPTION_KEY"])
            self.assertNotIn("DJANGO_ENCRYPTION_KEY", os.environ)

    def test_leaves_legitimate_value_untouched(self) -> None:
        path = self._env_file("DJANGO_SECRET_KEY=realsecret   # note\n")
        with mock.patch.dict(os.environ, {"DJANGO_SECRET_KEY": "realsecret"}, clear=False):
            removed = self._guard(Path(path))

            self.assertEqual(removed, [])
            self.assertEqual(os.environ["DJANGO_SECRET_KEY"], "realsecret")

    def test_hash_leading_value_is_treated_as_pollution(self) -> None:
        """Documented limitation (#364): a `#`-leading value is indistinguishable from a leaked
        comment at the value level, so the guard unsets it too. Dev-only and fails safe (unset,
        never a wrong value); no config key here legitimately starts with `#`."""
        path = self._env_file("SOME_COLOR=#ffffff\n")
        with mock.patch.dict(os.environ, {"SOME_COLOR": "#ffffff"}, clear=False):
            removed = self._guard(Path(path))

            self.assertEqual(removed, ["SOME_COLOR"])
            self.assertNotIn("SOME_COLOR", os.environ)

    def test_does_not_strip_var_set_in_real_environment(self) -> None:
        """override=False: a var already in the real environment keeps its real value even if the
        file has a comment-polluted line for the same key."""
        path = self._env_file("HMAC_SECRET=   # placeholder\n")
        # The real environment already has the true secret; the file line must not clobber it.
        with mock.patch.dict(os.environ, {"HMAC_SECRET": "the-real-secret"}, clear=False):
            removed = self._guard(Path(path))

            self.assertEqual(removed, [])
            self.assertEqual(os.environ["HMAC_SECRET"], "the-real-secret")


class TestEnvTemplateHygiene(TestCase):
    """#364: no .env.example.* template may ship an empty-value var with an inline comment."""

    def test_no_empty_value_inline_comments_in_templates(self) -> None:
        offenders: list[str] = []
        templates = sorted(_REPO_ROOT.glob(".env.example*"))
        # A broken glob or repo-layout change must fail loudly, not scan zero files and pass.
        self.assertGreaterEqual(len(templates), 3, f"expected the .env.example templates at {_REPO_ROOT}")
        for template in templates:
            for lineno, line in enumerate(template.read_text().splitlines(), start=1):
                if _EMPTY_VALUE_INLINE_COMMENT.match(line):
                    offenders.append(f"{template.name}:{lineno}: {line}")

        self.assertEqual(
            offenders,
            [],
            "empty-value vars with inline comments corrupt to '# ...' under dotenv (#364); "
            "move the comment to its own line:\n" + "\n".join(offenders),
        )

    def test_pattern_catches_export_and_indented_variants(self) -> None:
        """The guardrail must reject the variants dotenv also leaks, not just the bare form."""
        for line in (
            "KEY=   # note",
            "KEY=# note",
            "\tKEY=   # note",
            "  KEY= # note",
            "export KEY=   # note",
        ):
            self.assertIsNotNone(_EMPTY_VALUE_INLINE_COMMENT.match(line), line)
        for ok in (
            "KEY=value   # note",  # non-empty value: dotenv strips the comment, fine
            "# a standalone comment line",
            "KEY=",
        ):
            self.assertIsNone(_EMPTY_VALUE_INLINE_COMMENT.match(ok), ok)
