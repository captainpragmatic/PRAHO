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
import inspect
import sys
import tempfile
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

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
        source = f'def write(key, value):\n    SettingsService.update_setting(key, value)\nwrite("{KEY}", True)\n'
        self.assertIn(KEY, lint._written_keys(source))

    def test_a_helper_whose_key_is_its_second_argument_credits_the_second(self) -> None:
        """`def write(value, key)` must not credit whatever happens to be written first."""
        source = f'def write(value, key):\n    SettingsService.update_setting(key, value)\nwrite("{KEY}", "{OTHER}")\n'
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


class ReaderReachabilityTests(SimpleTestCase):
    """An effect is observed through the code that READS the key, not merely "another app"."""

    GRAPH: ClassVar[dict[str, set[str]]] = {
        "apps.api.localisation.views": {"apps.common.localisation_services"},
        "apps.common.localisation_services": {"apps.settings.services"},
        "apps.orders.tasks": {"apps.settings.services"},
        "apps.unrelated.views": {"apps.customers.models"},
    }

    def test_the_reader_itself_is_reached(self) -> None:
        self.assertTrue(lint.reaches_reader("apps.orders.tasks", {"apps.orders.tasks"}, self.GRAPH))

    def test_a_reader_one_hop_away_is_reached(self) -> None:
        """`test_localisation_api.py` goes through the API view, which calls the reading module."""
        self.assertTrue(
            lint.reaches_reader("apps.api.localisation.views", {"apps.common.localisation_services"}, self.GRAPH)
        )

    def test_an_unrelated_module_does_not_reach_the_reader(self) -> None:
        self.assertFalse(lint.reaches_reader("apps.unrelated.views", {"apps.orders.tasks"}, self.GRAPH))

    def test_depth_is_bounded(self) -> None:
        graph = {"a": {"b"}, "b": {"c"}, "c": {"d"}}
        self.assertTrue(lint.reaches_reader("a", {"c"}, graph, depth=2))
        self.assertFalse(lint.reaches_reader("a", {"d"}, graph, depth=2))

    def test_a_module_path_becomes_a_dotted_name(self) -> None:
        self.assertEqual(lint._module_name("services/platform/apps/orders/tasks.py"), "apps.orders.tasks")


class EffectCreditScopeTests(SimpleTestCase):
    """The write and the observation must belong to the SAME class.

    File scope was the defect an external review found: eight keys held credit because a write in one
    class was qualified by an unrelated request or import in another. Each test below is one of those
    shapes, reduced to its essentials.
    """

    KEY = "orders.card_timeout_hours"
    READERS: ClassVar[dict[str, set[str]]] = {KEY: {"apps.orders.tasks"}}
    GRAPH: ClassVar[dict[str, set[str]]] = {"apps.orders.tasks": set(), "apps.audit.views": set()}

    def credit(self, source: str) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test_probe.py"
            path.write_text(source)
            return lint.effect_tested_keys({self.KEY}, [path], self.READERS, self.GRAPH, set())

    def test_a_write_observed_through_the_reader_in_the_same_class_earns_credit(self) -> None:
        source = (
            "from apps.orders.tasks import process_pending_orders\n"
            "class T:\n"
            f'    def test_x(self):\n        SettingsService.update_setting("{self.KEY}", 6)\n'
            "        process_pending_orders()\n"
        )
        self.assertIn(self.KEY, self.credit(source))

    def test_a_write_qualified_by_a_different_class_earns_nothing(self) -> None:
        """The exact shape of the eight false credits."""
        source = (
            "from apps.orders.tasks import process_pending_orders\n"
            "class Writes:\n"
            f'    def test_x(self):\n        SettingsService.update_setting("{self.KEY}", 6)\n'
            "class Observes:\n"
            "    def test_y(self):\n        process_pending_orders()\n"
        )
        self.assertNotIn(self.KEY, self.credit(source))

    def test_a_write_observed_through_an_unrelated_module_earns_nothing(self) -> None:
        source = (
            "from apps.audit.views import audit_list\n"
            "class T:\n"
            f'    def test_x(self):\n        SettingsService.update_setting("{self.KEY}", 6)\n'
            "        audit_list()\n"
        )
        self.assertNotIn(self.KEY, self.credit(source))

    def test_a_read_back_earns_nothing(self) -> None:
        """Writing then reading the key back proves storage, which other checks already cover."""
        source = (
            "class T:\n"
            f'    def test_x(self):\n        SettingsService.update_setting("{self.KEY}", 6)\n'
            f'        self.assertEqual(SettingsService.get_integer_setting("{self.KEY}", 0), 6)\n'
        )
        self.assertNotIn(self.KEY, self.credit(source))

    def test_a_template_only_key_is_earned_by_rendering_a_page(self) -> None:
        source = (
            "class T:\n"
            '    def test_x(self):\n        SettingsService.update_setting("company.legal_name", "X SRL")\n'
            '        self.client.get("/privacy-policy/")\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test_probe.py"
            path.write_text(source)
            credited = lint.effect_tested_keys({"company.legal_name"}, [path], {}, {}, {"company.legal_name"})
        self.assertIn("company.legal_name", credited)

    def test_a_module_level_key_collection_the_class_uses_counts_as_written(self) -> None:
        """`PRIVACY_KEYS = {...}` iterated by the class; seven company keys depend on this."""
        source = (
            "from apps.orders.tasks import process_pending_orders\n"
            f'KEYS = {{"{self.KEY}": 6}}\n'
            "class T:\n"
            "    def test_x(self):\n        for k, v in KEYS.items():\n"
            "            SettingsService.update_setting(k, v)\n"
            "        process_pending_orders()\n"
        )
        self.assertIn(self.KEY, self.credit(source))


class InertSettingDetectionTests(SimpleTestCase):
    """Check 6 must refuse to judge where it cannot see, and must still catch the plain case."""

    KEYS = frozenset({KEY, OTHER, "example.dead_setting", "orders.review_threshold_cents"})

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
            'def get_dead():\n    return SettingsService.get_integer_setting("example.dead_setting", 1)\n'
        )
        self.assertIn("example.dead_setting", self.flagged({"dead.py": source}))

    def test_a_called_getter_is_not_reported(self) -> None:
        source = (
            "from apps.settings.services import SettingsService\n"
            'def get_live():\n    return SettingsService.get_integer_setting("example.dead_setting", 1)\n'
            "def enforce():\n    return get_live() > 0\n"
        )
        self.assertNotIn("example.dead_setting", self.flagged({"live.py": source}))

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
            'def get_budget():\n    return SettingsService.get_integer_setting("example.dead_setting", 1)\n'
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
        self.assertIn("example.dead_setting", {f.name for f in findings if f.severity == "medium"})


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


class FoundationReaderDetectionTests(SimpleTestCase):
    """Seeded sources exercise detection and credit without importing fixture application code."""

    def scan(self, sources: dict[str, str]) -> list[lint.SettingsCallSite]:
        exported = getattr(lint, "_exported_key_symbols", None)
        if exported is not None:
            exported.cache_clear()
        original = Path.read_text
        paths = {lint.PLATFORM_DIR / name: source for name, source in sources.items()}

        def read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
            return paths[path] if path in paths else original(path, encoding=encoding, errors=errors)

        with patch.object(Path, "read_text", autospec=True, side_effect=read):
            return lint.collect_settings_calls(list(paths))

    def findings(self, calls: list[lint.SettingsCallSite], known: set[str] | None = None) -> list[lint.Finding]:
        # Keep the reproduction assertion reachable on the pre-foundation API.
        options = (
            {"reader_baseline": known or set(), "call_sites": calls}
            if "reader_baseline" in inspect.signature(lint.check_untested_effects).parameters
            else {}
        )
        return lint.check_untested_effects({KEY, OTHER}, [], set(), {}, {}, set(), **options)

    def test_row_only_readers_are_detected_without_default_drift(self) -> None:
        for reader in ("SystemSetting.get_value_by_key", "SettingsService.get_stored_setting"):
            with self.subTest(reader=reader):
                argument = f'"{KEY}", None' if reader.endswith("get_value_by_key") else f'"{KEY}"'
                calls = self.scan({"apps/probe.py": f"value = {reader}({argument})\n"})
                self.assertEqual([(c.key, c.file) for c in calls], [(KEY, "services/platform/apps/probe.py")])
                self.assertEqual(lint.check_default_drift({KEY: True}, calls), [])

    def test_literal_module_and_class_constants_are_read_only_at_calls(self) -> None:
        calls = self.scan(
            {
                "apps/probe.py": f'KEY = "{KEY}"\nclass Keys:\n    ISSUER = "{OTHER}"\n'
                "unused = Keys.ISSUER\nvalue = SettingsService.get_boolean_setting(KEY, False)\n"
                'other = SettingsService.get_setting(Keys.ISSUER, "builtin")\n'
            }
        )
        self.assertEqual([c.key for c in calls], [KEY, OTHER])
        self.assertEqual(len(self.scan({"apps/probe.py": f'class Keys:\n    FLAG = "{KEY}"\n'})), 0)

    def test_bounded_forwarding_preserves_argument_position_and_consumer(self) -> None:
        source = (
            "class Resolver:\n"
            "    def row(self, unused, key):\n        return SystemSetting.get_value_by_key(key, None)\n"
            "    def flag(self, key):\n        return self.row(None, key=key)\n"
            f'    def enabled(self):\n        return self.flag("{KEY}")\n'
            "class Unrelated:\n"
            "    def flag(self, key):\n        return False\n"
            f'    def enabled(self):\n        return self.flag("{OTHER}")\n'
        )
        calls = self.scan({"apps/probe.py": source})
        self.assertEqual([(c.key, c.file) for c in calls], [(KEY, "services/platform/apps/probe.py")])
        self.assertEqual(lint.production_readers([]), {})

    def test_finite_key_map_reads_all_values_but_membership_is_not_a_reader(self) -> None:
        source = (
            f'class Keys:\n    FLAG = "{KEY}"\n    ISSUER = "{OTHER}"\n'
            "def lookup(kind):\n"
            '    mapping = {"flag": Keys.FLAG, "issuer": Keys.ISSUER}\n'
            "    if kind in mapping:\n        return SystemSetting.get_value_by_key(mapping[kind], None)\n"
        )
        calls = self.scan({"apps/probe.py": source})
        self.assertEqual({c.key for c in calls}, {KEY, OTHER})
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            self.scan(
                {
                    "apps/probe.py": source.replace(
                        "return SystemSetting.get_value_by_key(mapping[kind], None)", "return kind in mapping"
                    )
                }
            ),
            [],
        )

    def test_imported_named_keys_and_persisted_writes_earn_consumer_credit(self) -> None:
        sources = {
            "apps/keys.py": f'class Keys:\n    FLAG = "{KEY}"\nMODULE_KEY = "{OTHER}"\n',
            "apps/probe.py": (
                "from apps.keys import Keys as Names, MODULE_KEY as ISSUER\n"
                "def run():\n    return SystemSetting.get_value_by_key(Names.FLAG, None)\n"
                "def issue():\n    return SettingsService.get_stored_setting(ISSUER)\n"
            ),
        }
        calls = self.scan(sources)
        self.assertEqual({c.key for c in calls}, {KEY, OTHER})
        fixture = (
            "from apps.keys import Keys as Names, MODULE_KEY as ISSUER\n"
            "from apps.probe import run, issue\n"
            "class Effect:\n"
            "    def test_effect(self):\n"
            "        SystemSetting.objects.update_or_create(key=Names.FLAG, defaults={'value': True})\n"
            "        SettingsService.update_setting(ISSUER, 'external')\n"
            "        self.assertTrue(run())\n        self.assertEqual(issue(), 'external')\n"
        )
        original = Path.read_text
        paths = {lint.PLATFORM_DIR / name: source for name, source in sources.items()}
        test_path = lint.PLATFORM_TESTS_DIR / "test_probe.py"
        paths[test_path] = fixture

        def read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
            return paths[path] if path in paths else original(path, encoding=encoding, errors=errors)

        with patch.object(Path, "read_text", autospec=True, side_effect=read):
            self.assertEqual(
                lint.effect_tested_keys(
                    {KEY, OTHER}, [test_path], {KEY: {"apps.probe"}, OTHER: {"apps.probe"}}, {}, set()
                ),
                {KEY, OTHER},
            )
            paths[test_path] = fixture.replace("SystemSetting.objects.update_or_create", "Mock.objects.get")
            self.assertEqual(
                lint.effect_tested_keys({KEY}, [test_path], {KEY: {"apps.probe"}}, {}, set()),
                set(),
            )
            paths[test_path] = fixture.replace(
                "from apps.probe import run, issue", "from apps.unrelated import run, issue"
            )
            self.assertEqual(lint.effect_tested_keys({KEY}, [test_path], {KEY: {"apps.probe"}}, {}, set()), set())

    def test_new_untested_reader_fails_at_medium(self) -> None:
        calls = self.scan({"apps/probe.py": f'value = SettingsService.get_setting("{OTHER}", "builtin")\n'})
        self.assertEqual(
            [(f.check, f.severity, f.name) for f in self.findings(calls) if f.severity == "medium"],
            [("untested-new-reader", "medium", OTHER)],
        )
        old = self.scan({"apps/old.py": f'value = SettingsService.get_setting("{KEY}", False)\n'})
        new = self.scan({"apps/new.py": f'value = SettingsService.get_setting("{KEY}", False)\n'})
        locations = getattr(lint, "reader_locations", lambda _calls: {})
        options = (
            {"reader_baseline": set(locations(old)), "call_sites": old + new}
            if "reader_baseline" in inspect.signature(lint.check_untested_effects).parameters
            else {}
        )
        fixture = (
            "from apps.old import enforce\nclass Effect:\n"
            f'    def test_effect(self):\n        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(enforce())\n"
        )
        with patch.object(Path, "read_text", return_value=fixture):
            findings = lint.check_untested_effects(
                {KEY},
                [lint.PLATFORM_TESTS_DIR / "test_probe.py"],
                {KEY},
                {KEY: {"apps.old", "apps.new"}},
                {},
                set(),
                **options,
            )
        self.assertEqual(
            [(f.file, f.check, f.severity) for f in findings if f.severity == "medium"],
            [("services/platform/apps/new.py", "untested-new-reader", "medium")],
        )

    def test_existing_key_new_read_in_same_function_is_not_grandfathered(self) -> None:
        source = f'def run():\n    return SettingsService.get_setting("{KEY}", False)\n'
        old = self.scan({"apps/probe.py": source})
        locations = getattr(lint, "reader_locations", lambda _calls: {})
        known = set(locations(old))
        new = self.scan({"apps/probe.py": source + f'    value = SettingsService.get_setting("{KEY}", False)\n'})
        self.assertEqual(
            [(f.check, f.severity, f.name) for f in self.findings(new, known) if f.severity == "medium"],
            [("untested-new-reader", "medium", KEY)],
        )
        self.assertEqual([f for f in self.findings(old, known) if f.severity == "medium"], [])

    def test_removing_a_credited_row_reader_effect_test_fails(self) -> None:
        calls = self.scan({"apps/probe.py": f'value = SettingsService.get_stored_setting("{KEY}")\n'})
        self.assertEqual([c.key for c in calls], [KEY])
        path = lint.PLATFORM_TESTS_DIR / "test_probe.py"
        source = (
            "from apps.probe import run\n"
            "class Effect:\n"
            f'    def test_effect(self):\n        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(run())\n"
        )
        readers = {KEY: {"apps.probe"}}
        with patch.object(Path, "read_text", return_value=source):
            self.assertEqual(lint.effect_tested_keys({KEY}, [path], readers, {}, set()), {KEY})
            self.assertEqual(
                [
                    f
                    for f in lint.check_untested_effects({KEY}, [path], {KEY}, readers, {}, set())
                    if f.severity == "medium"
                ],
                [],
            )
        findings = lint.check_untested_effects({KEY}, [], {KEY}, readers, {}, set())
        self.assertEqual(
            [(f.check, f.severity, f.name) for f in findings if f.severity == "medium"],
            [("untested-effect-regression", "medium", KEY)],
        )
