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
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
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

    def test_reader_baseline_writer_rebuilds_debt_and_keeps_the_ratchet(self) -> None:
        app_a = lint.APPS_DIR / "reader_a.py"
        app_z = lint.APPS_DIR / "reader_z.py"
        test_path = lint.PLATFORM_TESTS_DIR / "common" / "test_reader_probe.py"
        baseline = lint.PROJECT_ROOT / "scripts" / "reader_probe_baseline.txt"
        texts = {
            app_a: (
                "from apps.settings.services import SettingsService\n"
                "class Consumer:\n"
                f'    def tested(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
                f'    def sibling(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
                "    def duplicate(self):\n"
                f'        first = SettingsService.get_setting("{OTHER}", "builtin")\n'
                f'        return first, SettingsService.get_setting("{OTHER}", "builtin")\n'
                "    def retired(self):\n        return SettingsService.get_setting('retired.flag', False)\n"
            ),
            app_z: (
                "from apps.settings.services import SettingsService\n"
                "class Consumer:\n"
                f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            ),
            test_path: (
                "from apps.reader_a import Consumer\n"
                "class Effect:\n"
                "    def test_effect(self):\n"
                f'        SettingsService.update_setting("{KEY}", True)\n'
                "        reader = Consumer()\n        self.assertTrue(reader.tested())\n"
            ),
            baseline: (f"@ services/platform/apps/reader_z.py\n{KEY}|Consumer.read|1\nobsolete.flag|Removed.read|1\n"),
            lint.DEFAULT_READER_BASELINE: "# Leave the default reader baseline unchanged.\n",
            lint.DEFAULT_ALLOWLIST: "",
            lint.DEFAULT_EFFECT_BASELINE: "",
            lint.DEFAULT_DRIFT_BASELINE: "",
            lint.DEFAULT_INERT_BASELINE: "",
        }
        original_read = Path.read_text
        original_exists = Path.exists

        def read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
            return texts[path] if path in texts else original_read(path, encoding=encoding, errors=errors)

        def write(path: Path, data: str, encoding: str | None = None, errors: str | None = None) -> int:
            texts[path] = data
            return len(data)

        def exists(path: Path) -> bool:
            return path in texts or original_exists(path)

        def files(root: Path) -> list[Path]:
            return [test_path] if root == lint.PLATFORM_TESTS_DIR else [app_z, app_a]

        def run(*options: str) -> int | str | None:
            output = StringIO()
            argv = ["lint_settings_coverage.py", "--reader-baseline", str(baseline), *options]
            with patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
                try:
                    return lint.main()
                except SystemExit as exc:
                    return exc.code

        with (
            patch.object(Path, "read_text", autospec=True, side_effect=read),
            patch.object(Path, "write_text", autospec=True, side_effect=write),
            patch.object(Path, "exists", autospec=True, side_effect=exists),
            patch.object(lint, "iter_python_files", side_effect=files),
            patch.object(lint, "iter_template_files", return_value=[]),
            patch.object(lint, "extract_default_settings", return_value={KEY: False, OTHER: "builtin"}),
            patch.object(lint, "extract_catalog_keys", return_value={KEY, OTHER}),
        ):
            self.assertEqual(run("--write-reader-baseline"), 0)
            recorded = texts[baseline]
            self.assertEqual(
                [line for line in recorded.splitlines() if line and not line.startswith("#")],
                [
                    "@ services/platform/apps/reader_a.py",
                    f"{OTHER}|Consumer.duplicate|1",
                    f"{OTHER}|Consumer.duplicate|2",
                    f"{KEY}|Consumer.sibling|1",
                    "@ services/platform/apps/reader_z.py",
                    f"{KEY}|Consumer.read|1",
                ],
            )
            self.assertEqual(len(lint.load_reader_baseline(baseline)), 4)
            self.assertEqual(texts[lint.DEFAULT_READER_BASELINE], "# Leave the default reader baseline unchanged.\n")
            self.assertEqual(run("--write-reader-baseline"), 0)
            self.assertEqual(texts[baseline], recorded)
            self.assertEqual(run("--fail-on", "medium"), 0)
            self.assertEqual(texts[baseline], recorded)
            texts[app_z] += f'    def new(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            self.assertEqual(run("--fail-on", "medium"), 1)
            self.assertEqual(texts[baseline], recorded)

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

    def test_tested_callable_does_not_credit_an_untested_sibling(self) -> None:
        sources = {
            "apps/probe.py": (
                "from apps.settings.services import SettingsService\n"
                f'def tested():\n    return SettingsService.get_boolean_setting("{KEY}", False)\n'
                f'def untested_sibling():\n    return SettingsService.get_boolean_setting("{KEY}", False)\n'
            )
        }
        calls = self.scan(sources)
        self.assertEqual([call.scope for call in calls], ["tested", "untested_sibling"])
        known = set(lint.reader_locations(calls[:1]))
        for import_line, invocation in (
            ("from apps.probe import tested", "tested()"),
            ("from apps.probe import tested as exercised", "exercised()"),
            ("import apps.probe as probe", "probe.tested()"),
        ):
            with self.subTest(import_line=import_line):
                fixture = (
                    f"{import_line}\nclass Effect:\n"
                    f'    def test_effect(self):\n        SettingsService.update_setting("{KEY}", True)\n'
                    f"        self.assertTrue({invocation})\n"
                )
                path = lint.PLATFORM_TESTS_DIR / "test_probe.py"
                with patch.object(Path, "read_text", return_value=fixture):
                    findings = lint.check_untested_effects(
                        {KEY},
                        [path],
                        {KEY},
                        {KEY: {"apps.probe"}},
                        {},
                        set(),
                        reader_baseline=known,
                        call_sites=calls,
                    )
                self.assertEqual(
                    [
                        (finding.check, finding.severity, finding.line)
                        for finding in findings
                        if finding.severity == "medium"
                    ],
                    [("untested-new-reader", "medium", calls[1].line)],
                )
                self.assertIn("untested_sibling", findings[0].message)
                with patch.object(Path, "read_text", return_value=fixture):
                    findings = lint.check_untested_effects(
                        {KEY},
                        [path],
                        set(),
                        {KEY: {"apps.probe"}},
                        {},
                        set(),
                        call_sites=calls,
                    )
                self.assertEqual(
                    [finding.line for finding in findings if finding.check == "untested-new-reader"],
                    [calls[1].line],
                )

    def test_wrapper_credit_follows_callable_edges_without_crediting_siblings(self) -> None:
        sources = {
            "apps/probe.py": (
                "from apps.settings.services import SettingsService\n"
                f'def tested():\n    return SettingsService.get_boolean_setting("{KEY}", False)\n'
                f'def untested_sibling():\n    return SettingsService.get_boolean_setting("{KEY}", False)\n'
                "def entrypoint():\n    return tested()\n"
            )
        }
        calls = self.scan(sources)
        fixture = (
            "from apps.probe import entrypoint\nclass Effect:\n"
            f'    def test_effect(self):\n        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(entrypoint())\n"
        )
        path = lint.PLATFORM_DIR / "apps/probe.py"
        test_path = lint.PLATFORM_TESTS_DIR / "test_probe.py"
        texts = {path: sources["apps/probe.py"], test_path: fixture}

        original = Path.read_text

        def read(file: Path, encoding: str | None = None, errors: str | None = None) -> str:
            return texts[file] if file in texts else original(file, encoding=encoding, errors=errors)

        with patch.object(Path, "read_text", autospec=True, side_effect=read):
            graph = lint.production_import_graph([path])
            findings = lint.check_untested_effects(
                {KEY},
                [test_path],
                {KEY},
                {KEY: {"apps.probe"}},
                graph,
                set(),
                call_sites=calls,
            )
        self.assertEqual(
            [(finding.check, finding.severity, finding.line) for finding in findings if finding.severity == "medium"],
            [("untested-new-reader", "medium", calls[1].line)],
        )

    def test_decorator_factory_credit_requires_applying_what_it_returns(self) -> None:
        source = (
            "from apps.settings.services import SettingsService\n"
            f'def _checks():\n    return SettingsService.get_boolean_setting("{KEY}", False)\n'
            "def factory():\n"
            "    def decorator(func):\n"
            "        def wrapper(*args, **kwargs):\n"
            "            _checks()\n"
            "            return func(*args, **kwargs)\n"
            "        return wrapper\n"
            "    return decorator\n"
            "def registration():\n    return factory()\n"
            "def defined_only():\n"
            "    def unused():\n"
            "        return _checks()\n"
            "    return 1\n"
        )
        # A decorated consumer in another module, the shape of SecureUserRegistrationService.
        service = "from apps.probe import registration\n@registration()\ndef service():\n    return True\n"
        calls = self.scan({"apps/probe.py": source})
        path = lint.PLATFORM_DIR / "apps/probe.py"
        service_path = lint.PLATFORM_DIR / "apps/service.py"
        test_path = lint.PLATFORM_TESTS_DIR / "test_probe.py"
        original = Path.read_text
        untested = [calls[0].line]
        scenarios = (
            ("factory called, result never applied", "apps.probe", "registration", "registration()", untested),
            ("result applied", "apps.probe", "registration", "registration()(lambda: True)()", []),
            ("decorated in the test", "apps.probe", "registration", "registration()(lambda: True)", []),
            ("decorated consumer", "apps.service", "service", "service()", []),
            ("nested def never returned", "apps.probe", "defined_only", "defined_only()", untested),
        )
        for label, module, name, expression, expected in scenarios:
            with self.subTest(label):
                body = f"        self.assertTrue({expression})\n"
                if label == "decorated in the test":
                    body = "        @registration()\n        def local():\n            return True\n        local()\n"
                fixture = (
                    f"from {module} import {name}\nclass Effect:\n"
                    f'    def test_effect(self):\n        SettingsService.update_setting("{KEY}", True)\n' + body
                )
                texts = {path: source, service_path: service, test_path: fixture}

                def read(
                    file: Path, encoding: str | None = None, errors: str | None = None, texts: dict[Path, str] = texts
                ) -> str:
                    return texts[file] if file in texts else original(file, encoding=encoding, errors=errors)

                with patch.object(Path, "read_text", autospec=True, side_effect=read):
                    graph = lint.production_import_graph([path, service_path])
                    findings = lint.check_untested_effects(
                        {KEY}, [test_path], {KEY}, {KEY: {"apps.probe"}}, graph, set(), call_sites=calls
                    )
                self.assertEqual(
                    [finding.line for finding in findings if finding.check == "untested-new-reader"], expected
                )

    def consumer_findings(
        self, sources: dict[str, str], fixture: str
    ) -> tuple[list[lint.SettingsCallSite], list[lint.Finding]]:
        calls = self.scan(sources)
        texts = {lint.PLATFORM_DIR / name: source for name, source in sources.items()}
        test_path = lint.PLATFORM_TESTS_DIR / "common" / "test_probe.py"
        texts[test_path] = fixture
        original = Path.read_text

        def read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
            return texts[path] if path in texts else original(path, encoding=encoding, errors=errors)

        with patch.object(Path, "read_text", autospec=True, side_effect=read):
            graph = lint.production_import_graph([lint.PLATFORM_DIR / name for name in sources])
            findings = lint.check_untested_effects(
                {KEY}, [test_path], {KEY}, {KEY: {"apps.probe", "apps.other"}}, graph, set(), call_sites=calls
            )
        return calls, findings

    def test_method_imports_do_not_resolve_calls_in_sibling_scopes(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
        )
        for shadow_scope in ("method", "class", "closure"):
            with self.subTest(shadow_scope=shadow_scope):
                shadow = {
                    "method": (
                        "    def test_name(self):\n"
                        "        from apps.probe import Consumer\n"
                        "        self.assertEqual(Consumer.__name__, 'Consumer')\n"
                    ),
                    "class": (
                        "class NamesOnly:\n"
                        "    from apps.probe import Consumer\n"
                        "    def test_name(self):\n"
                        "        self.assertEqual(self.Consumer.__name__, 'Consumer')\n"
                    ),
                    "closure": (
                        "    def test_name(self):\n"
                        "        def unused():\n"
                        "            from apps.probe import Consumer\n"
                        "            return Consumer.__name__\n"
                        "        self.assertTrue(callable(unused))\n"
                    ),
                }[shadow_scope]
                module_import = "" if shadow_scope == "method" else "from apps.other import Consumer\n"
                method_import = "        from apps.other import Consumer\n" if shadow_scope == "method" else ""
                fixture = (
                    f"{module_import}class Effect:\n"
                    "    def test_effect(self):\n"
                    f'        SettingsService.update_setting("{KEY}", True)\n'
                    f"{method_import}        self.assertTrue(Consumer().read())\n"
                    f"{shadow}"
                )
                calls, findings = self.consumer_findings({"apps/probe.py": source, "apps/other.py": source}, fixture)
                self.assertEqual([call.scope for call in calls], ["Consumer.read", "Consumer.read"])
                self.assertEqual(
                    [(f.file, f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
                    [(calls[0].file, "untested-new-reader", "medium", calls[0].line)],
                )

    def test_production_wrapper_imports_do_not_leak_from_sibling_functions(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
        )
        wrapper = (
            "from apps.other import Consumer\n"
            "def entrypoint():\n    return Consumer().read()\n"
            "def names_only():\n"
            "    from apps.probe import Consumer\n"
            "    return Consumer.__name__\n"
        )
        fixture = (
            "from apps.entry import entrypoint\n"
            "class Effect:\n"
            "    def test_effect(self):\n"
            f'        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(entrypoint())\n"
        )
        calls, findings = self.consumer_findings(
            {"apps/probe.py": source, "apps/other.py": source, "apps/entry.py": wrapper}, fixture
        )
        self.assertEqual(
            [(f.file, f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
            [(calls[0].file, "untested-new-reader", "medium", calls[0].line)],
        )

    def test_local_instance_assignments_do_not_leak_between_methods(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
        )
        fixture = (
            "from apps.other import Consumer as OtherConsumer\n"
            "from apps.probe import Consumer\n"
            "class Effect:\n"
            "    def test_effect(self):\n"
            f'        SettingsService.update_setting("{KEY}", True)\n'
            "        consumer = OtherConsumer()\n"
            "        self.assertTrue(consumer.read())\n"
            "    def test_name(self):\n"
            "        consumer = Consumer()\n"
            "        self.assertEqual(consumer.__class__.__name__, 'Consumer')\n"
        )
        calls, findings = self.consumer_findings({"apps/probe.py": source, "apps/other.py": source}, fixture)
        self.assertEqual(
            [(f.file, f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
            [(calls[0].file, "untested-new-reader", "medium", calls[0].line)],
        )

    def test_setup_instances_credit_only_methods_exercised_in_the_same_class(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            f'    def sibling(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
        )
        for method, receiver in (("setUp", "self"), ("setUpTestData", "cls"), ("prepare", "self")):
            with self.subTest(method=method):
                decorator = "    @classmethod\n" if receiver == "cls" else ""
                prepare = "        self.prepare()\n" if method == "prepare" else ""
                fixture = (
                    "class Effect:\n"
                    f"{decorator}"
                    f"    def {method}({receiver}):\n"
                    "        from apps.probe import Consumer\n"
                    f"        {receiver}.consumer = Consumer()\n"
                    "    def test_effect(self):\n"
                    f'        SettingsService.update_setting("{KEY}", True)\n'
                    f"{prepare}        self.assertTrue(self.consumer.read())\n"
                )
                calls, findings = self.consumer_findings({"apps/probe.py": source}, fixture)
                self.assertEqual([call.scope for call in calls], ["Consumer.read", "Consumer.sibling"])
                self.assertEqual(
                    [(f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
                    [("untested-new-reader", "medium", calls[1].line)],
                )
                separate_class = fixture.replace(
                    "    def test_effect(self):", "class Uninitialised:\n    def test_effect(self):"
                )
                _, findings = self.consumer_findings({"apps/probe.py": source}, separate_class)
                self.assertEqual(
                    [f.line for f in findings if f.check == "untested-new-reader"],
                    [call.line for call in calls],
                )

    def test_a_test_methods_own_instance_does_not_replace_the_fixture_instance(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            "class OtherConsumer:\n"
            f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
        )
        fixture = (
            "from apps.probe import Consumer, OtherConsumer\n"
            "class Effect:\n"
            "    def setUp(self):\n"
            "        self.consumer = OtherConsumer()\n"
            "    def test_name_only(self):\n"
            "        self.consumer = Consumer()\n"
            '        self.assertEqual(type(self.consumer).__name__, "Consumer")\n'
            "    def test_effect(self):\n"
            f'        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(self.consumer.read())\n"
        )
        calls, findings = self.consumer_findings({"apps/probe.py": source}, fixture)
        self.assertEqual([call.scope for call in calls], ["Consumer.read", "OtherConsumer.read"])
        self.assertEqual(
            [(f.check, f.line) for f in findings if f.severity == "medium"],
            [("untested-new-reader", calls[0].line)],
        )

    def test_property_access_credits_only_resolved_property_getters(self) -> None:
        for import_line, decorator in (
            ("", "property"),
            ("from functools import cached_property\n", "cached_property"),
            ("from django.utils.functional import cached_property as memoized\n", "memoized"),
        ):
            with self.subTest(decorator=decorator):
                source = (
                    f"{import_line}class Consumer:\n"
                    f"    @{decorator}\n"
                    f'    def read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
                    f"    @{decorator}\n"
                    f'    def sibling(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
                    f'    def plain(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
                )
                fixture = (
                    "from apps.probe import Consumer\n"
                    "class Effect:\n"
                    "    def test_effect(self):\n"
                    f'        SettingsService.update_setting("{KEY}", True)\n'
                    "        consumer = Consumer()\n"
                    "        self.assertTrue(consumer.read)\n"
                    "        self.assertTrue(callable(consumer.plain))\n"
                    "        self.assertTrue(hasattr(Consumer.sibling, '__get__'))\n"
                )
                calls, findings = self.consumer_findings({"apps/probe.py": source}, fixture)
                self.assertEqual([c.scope for c in calls], ["Consumer.read", "Consumer.sibling", "Consumer.plain"])
                self.assertEqual(
                    [(f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
                    [("untested-new-reader", "medium", call.line) for call in calls[1:]],
                )
                _, findings = self.consumer_findings(
                    {"apps/probe.py": source}, fixture.replace("consumer.read)", "consumer.sibling)")
                )
                self.assertEqual(
                    [f.line for f in findings if f.check == "untested-new-reader"],
                    [calls[0].line, calls[2].line],
                )

    def test_property_credit_follows_getter_edges(self) -> None:
        source = (
            "class Consumer:\n"
            f'    def _read(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            f'    def sibling(self):\n        return SettingsService.get_boolean_setting("{KEY}", False)\n'
            "    @property\n"
            "    def read(self):\n        return self._read()\n"
        )
        fixture = (
            "from apps.probe import Consumer\n"
            "class Effect:\n"
            "    def setUp(self):\n        self.consumer = Consumer()\n"
            "    def test_effect(self):\n"
            f'        SettingsService.update_setting("{KEY}", True)\n'
            "        self.assertTrue(self.consumer.read)\n"
        )
        calls, findings = self.consumer_findings({"apps/probe.py": source}, fixture)
        self.assertEqual([call.scope for call in calls], ["Consumer._read", "Consumer.sibling"])
        self.assertEqual(
            [(f.check, f.severity, f.line) for f in findings if f.severity == "medium"],
            [("untested-new-reader", "medium", calls[1].line)],
        )

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
