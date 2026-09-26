"""Tests for the settings guardrail's own detectors (scripts/lint_settings_coverage.py).

The gate blocks builds at medium severity, and it has already had to be corrected twice for
claiming more than it could establish. Each test below pins a specific shape it once got wrong:

* Check 5 credited a READ as a write, because `key\\s*=\\s*"..."` matches
  `get_setting(key="...")` as readily as `update_setting(key="...")`. Two keys held a false effect
  credit on that basis, one of them from a MOCK's `side_effect` comparison - a test that stubs the
  settings read is the precise opposite of an effect test.
* Check 5's helper resolution assumed the key was the first argument, so `def write(value, key)`
  would have credited the wrong string.
* Check 6 claimed a function dead from a textual name sweep, which a decorator or dynamic dispatch
  defeats, and it ignored methods entirely - so a key a live method read could still be reported
  inert.

A detector that quietly over- or under-reports is worse than none, which is the whole reason these
exist rather than only the tests of the settings themselves.

Named for what it tests rather than mirroring `lint_settings_coverage.py`, because
`scripts/audit_test_layout.py` flags "coverage" in a test filename - a heuristic aimed at files
written to raise a number rather than to check behaviour, and a fair one to keep.
"""

from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SCRIPTS_DIR = str(_REPO_ROOT / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import lint_settings_coverage as lint  # noqa: E402

KEY = "system.maintenance_mode"
OTHER = "billing.invoice_issuer"


class WrittenKeyDetectionTests(SimpleTestCase):
    """What counts as writing a setting, which is what separates an effect test from a read-back."""

    def test_a_read_through_the_key_keyword_is_not_a_write(self) -> None:
        self.assertNotIn(KEY, lint._written_keys(f'SettingsService.get_setting(key="{KEY}")'))

    def test_a_catalog_definition_is_not_a_write(self) -> None:
        self.assertNotIn(KEY, lint._written_keys(f'SettingDef(key="{KEY}", data_type="boolean")'))

    def test_a_mock_side_effect_comparison_is_not_a_write(self) -> None:
        self.assertNotIn(KEY, lint._written_keys(f'if key == "{KEY}":\n    return 5\n'))

    def test_a_direct_update_is_a_write(self) -> None:
        self.assertIn(KEY, lint._written_keys(f'SettingsService.update_setting("{KEY}", True)'))

    def test_a_write_through_the_key_keyword_is_a_write(self) -> None:
        self.assertIn(KEY, lint._written_keys(f'SettingsService.update_setting(key="{KEY}", value=True)'))

    def test_a_module_constant_resolves_to_its_key(self) -> None:
        source = f'MAINTENANCE = "{KEY}"\nSettingsService.update_setting(MAINTENANCE, True)\n'
        self.assertIn(KEY, lint._written_keys(source))

    def test_a_helper_forwarding_its_first_argument_credits_that_argument(self) -> None:
        source = (
            "def write(key, value):\n"
            "    SettingsService.update_setting(key, value)\n"
            f'write("{KEY}", True)\n'
        )
        self.assertIn(KEY, lint._written_keys(source))

    def test_a_helper_whose_key_is_its_second_argument_credits_the_second(self) -> None:
        """`def write(value, key)` must not credit whatever happens to be written first."""
        source = (
            "def write(value, key):\n"
            "    SettingsService.update_setting(key, value)\n"
            f'write("{KEY}", "{OTHER}")\n'
        )
        written = lint._written_keys(source)
        self.assertIn(OTHER, written)
        self.assertNotIn(KEY, written)

    def test_self_does_not_shift_a_method_helper_argument_position(self) -> None:
        source = (
            "class T:\n"
            "    def set_value(self, key, value):\n"
            "        SettingsService.update_setting(key, value)\n"
            f'    def test_x(self):\n        self.set_value("{KEY}", True)\n'
        )
        self.assertIn(KEY, lint._written_keys(source))

    def test_a_class_level_key_constant_resolves(self) -> None:
        """`KEY = "app.x"` on a test class, written as `self.KEY`, is as ordinary as a module constant."""
        source = (
            "class T:\n"
            f'    NOREPLY = "{KEY}"\n'
            "    def setUp(self):\n"
            "        SettingsService.update_setting(self.NOREPLY, True)\n"
        )
        self.assertIn(KEY, lint._written_keys(source))


class ObservationOutsideSettingsTests(SimpleTestCase):
    """An effect must be observed outside the settings app: another app, or a rendered page."""

    def test_importing_another_app_qualifies(self) -> None:
        self.assertTrue(lint._reaches_another_app("from apps.billing.models import Invoice\n"))

    def test_importing_only_the_settings_app_does_not(self) -> None:
        self.assertFalse(lint._reaches_another_app("from apps.settings.services import SettingsService\n"))

    def test_requesting_a_page_outside_the_settings_app_qualifies(self) -> None:
        """The only shape available to a key whose sole consumer is `{% setting %}` in a template."""
        self.assertTrue(lint._reaches_another_app('self.client.get("/privacy-policy/")'))
        self.assertTrue(lint._reaches_another_app('self.client.get(reverse("privacy_policy"))'))

    def test_requesting_the_settings_app_s_own_pages_does_not(self) -> None:
        self.assertFalse(lint._reaches_another_app('self.client.post("/settings/save/", data)'))
        self.assertFalse(lint._reaches_another_app('self.client.get(reverse("settings:list"))'))


class InertSettingDetectionTests(SimpleTestCase):
    """Check 6 must refuse to judge where it cannot see, and must still catch the plain case."""

    KEYS = frozenset({KEY, OTHER, "users.credential_max_age_days", "orders.review_threshold_cents"})

    def flagged(self, sources: dict[str, str]) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in sources.items():
                (root / name).write_text(text)
            findings = lint.check_inert_settings(set(self.KEYS), sorted(root.glob("*.py")), set())
        return {finding.name for finding in findings if finding.severity == "medium"}

    def test_a_plainly_uncalled_getter_is_reported(self) -> None:
        source = (
            "from apps.settings.services import SettingsService\n"
            'def get_dead():\n    return SettingsService.get_integer_setting("users.credential_max_age_days", 1)\n'
        )
        self.assertIn("users.credential_max_age_days", self.flagged({"dead.py": source}))

    def test_a_called_getter_is_not_reported(self) -> None:
        source = (
            "from apps.settings.services import SettingsService\n"
            'def get_live():\n    return SettingsService.get_integer_setting("users.credential_max_age_days", 1)\n'
            "def enforce():\n    return get_live() > 0\n"
        )
        self.assertNotIn("users.credential_max_age_days", self.flagged({"live.py": source}))

    def test_a_decorated_getter_is_not_reported(self) -> None:
        """A decorator receives the function object, so its name need never appear again."""
        source = (
            "from apps.settings.services import SettingsService\n"
            "@register.simple_tag\n"
            f'def get_thing():\n    return SettingsService.get_integer_setting("{KEY}", 1)\n'
        )
        self.assertNotIn(KEY, self.flagged({"decorated.py": source}))

    def test_a_module_using_dynamic_dispatch_is_not_reported(self) -> None:
        source = (
            "from apps.settings.services import SettingsService\n"
            "from django.utils.module_loading import import_string\n"
            f'def get_other():\n    return SettingsService.get_integer_setting("{OTHER}", 1)\n'
            'handler = import_string("x.y")\n'
        )
        self.assertNotIn(OTHER, self.flagged({"dynamic.py": source}))

    def test_a_key_a_live_method_also_reads_is_not_reported(self) -> None:
        """The dead getter is real; the key is not inert, because a method still reads it."""
        source = (
            "from apps.settings.services import SettingsService\n"
            'def get_unused():\n    return SettingsService.get_integer_setting("orders.review_threshold_cents", 1)\n'
            "class Thing:\n"
            "    def run(self):\n"
            '        return SettingsService.get_integer_setting("orders.review_threshold_cents", 1)\n'
        )
        self.assertNotIn("orders.review_threshold_cents", self.flagged({"both.py": source}))

    def test_a_same_named_getter_in_another_module_does_not_make_this_one_live(self) -> None:
        """Three modules define `get_task_time_limit`; a call to one hid the other two."""
        dead = (
            "from apps.settings.services import SettingsService\n"
            'def get_budget():\n    return SettingsService.get_integer_setting("users.credential_max_age_days", 1)\n'
        )
        unrelated = (
            "from apps.settings.services import SettingsService\n"
            f'def get_budget():\n    return SettingsService.get_integer_setting("{OTHER}", 1)\n'
            "def caller():\n    return get_budget()\n"
        )
        # Different packages, so neither can see the other's definition.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a" / "mod.py").write_text(dead)
            (root / "b" / "mod.py").write_text(unrelated)
            findings = lint.check_inert_settings(set(self.KEYS), sorted(root.rglob("*.py")), set())
        self.assertIn("users.credential_max_age_days", {f.name for f in findings if f.severity == "medium"})


class DriftBaselineTests(SimpleTestCase):
    """Check 4 ratchets: a baselined drift is silent, an unlisted one fails, a fixed one nags."""

    def sites(self, key: str, fallback: int) -> list[lint.SettingsCallSite]:
        return [
            lint.SettingsCallSite(
                key=key, fallback_value=fallback, fallback_is_name=False, fallback_name="", line=1, file="x.py"
            )
        ]

    def test_an_unlisted_drift_fails_at_medium(self) -> None:
        findings = lint.check_default_drift({KEY: 5}, self.sites(KEY, 9), baseline=set())
        self.assertEqual([(f.check, f.severity) for f in findings], [("default-drift", "medium")])

    def test_a_baselined_drift_is_silent(self) -> None:
        self.assertEqual(lint.check_default_drift({KEY: 5}, self.sites(KEY, 9), baseline={KEY}), [])

    def test_a_baselined_key_that_no_longer_drifts_asks_to_be_removed(self) -> None:
        findings = lint.check_default_drift({KEY: 5}, self.sites(KEY, 5), baseline={KEY})
        self.assertEqual([(f.check, f.severity) for f in findings], [("default-drift-fixed", "low")])


class NamedFallbackResolutionTests(SimpleTestCase):
    """Check 2 rewards moving a fallback into a constant; check 4 used to stop looking there."""

    def test_a_module_level_constant_resolves(self) -> None:
        source = "_DEFAULT_SIZE = 100\nMAX = _DEFAULT_SIZE\n"
        constants = lint.module_literal_constants(ast.parse(source))
        self.assertEqual(constants["_DEFAULT_SIZE"], 100)
        self.assertEqual(constants["MAX"], 100, "one level of aliasing must resolve too")

    def test_an_annotated_assignment_resolves(self) -> None:
        self.assertEqual(lint.module_literal_constants(ast.parse("LIMIT: int = 7\n"))["LIMIT"], 7)

    def test_a_computed_value_stays_unresolved(self) -> None:
        self.assertNotIn("LIMIT", lint.module_literal_constants(ast.parse("LIMIT = other() * 2\n")))
