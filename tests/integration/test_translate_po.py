"""Regression tests for scripts/translate_po.py: the review-YAML round trip (generate -> apply)
and the compile step. Everything runs on a small fixture catalogue in a temp directory; the
real catalogues are never touched.

The fixture mirrors how `make i18n-extract` (makemessages --no-wrap) writes the real files:
msgid/msgstr lines are not wrapped, `#:` reference lines are, and obsolete entries sit at the
end. A whole-file rewrite through polib changes all three, whatever wrapwidth it uses.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml


def _load_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "translate_po.py"
    spec = importlib.util.spec_from_file_location("translate_po", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def tp():
    return _load_module()


PO_REL = Path("services/platform/locale/ro/LC_MESSAGES/django.po")

HEADER = """\
# SOME DESCRIPTIVE TITLE.
#
#, fuzzy
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"
"Plural-Forms: nplurals=3; plural=(n==1?0:(((n%100>19)||((n%100==0)&&(n!=0)))?2:1));\\n"
"""

LONG_ENTRY = """\
#: apps/billing/invoice_models.py:90 apps/billing/proforma_models.py:110
#: apps/billing/views.py:2000 apps/notifications/models.py:519
msgid "Your data export request has been created. You will receive an email when it is ready for download."
msgstr "Solicitarea dvs. de export al datelor a fost creată. Veți primi un e-mail când va fi gata pentru descărcare."
"""

TEMPLATE_ENTRY = """\
#: templates/customers/list.html:53
#, python-format
msgid ""
"\\n"
"      %(total)s customer in total\\n"
"      "
msgstr ""
"\\n"
"      %(total)s client în total\\n"
"      "
"""

CONTEXT_CASH = """\
#: apps/billing/reports.py:20
msgctxt "revenue basis"
msgid "Cash"
msgstr ""
"""

BARE_CASH = """\
#: apps/billing/reports.py:10
msgid "Cash"
msgstr "Numerar"
"""

TRANSLATED_PLURAL = """\
#: apps/billing/views.py:30
#, python-format
msgid "%(count)s invoice"
msgid_plural "%(count)s invoices"
msgstr[0] "%(count)s factură"
msgstr[1] "%(count)s facturi"
msgstr[2] "%(count)s de facturi"
"""

EMPTY_PLURAL = """\
#: apps/billing/views.py:40
#, python-format
msgid "%(count)s order"
msgid_plural "%(count)s orders"
msgstr[0] ""
msgstr[1] ""
msgstr[2] ""
"""

REFUND = """\
#: apps/billing/views.py:50
msgid "Refund"
msgstr ""
"""

FUZZY = """\
#: apps/billing/views.py:60
#, fuzzy, python-format
msgid "Invoice %(number)s"
msgstr "Proformă %(number)s"
"""

OBSOLETE = """\
#, python-brace-format
#~ msgid "Retry failed: {message}"
#~ msgstr "Reîncercarea a eșuat: {message}"

#~ msgid "Archived note"
#~ msgstr ""
"""

ENTRIES = [LONG_ENTRY, TEMPLATE_ENTRY, CONTEXT_CASH, BARE_CASH, TRANSLATED_PLURAL, EMPTY_PLURAL, REFUND, FUZZY]


def _catalogue(*blocks: str) -> str:
    return "\n".join([HEADER, *blocks])


ORIGINAL = _catalogue(*ENTRIES, OBSOLETE)


@pytest.fixture()
def project(tmp_path, monkeypatch):
    """A temp repo root holding the fixture catalogue at its real relative path."""
    monkeypatch.chdir(tmp_path)
    po = tmp_path / PO_REL
    po.parent.mkdir(parents=True)
    po.write_bytes(ORIGINAL.encode("utf-8"))
    return tmp_path


def _write_review(path: Path, entries: list[dict]) -> Path:
    for entry in entries:
        entry.setdefault("status", "approved")
    path.write_text(
        yaml.dump({"metadata": {"po_file": str(PO_REL)}, "entries": entries}, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def _po_text(project: Path) -> str:
    return (project / PO_REL).read_bytes().decode("utf-8")


class TestApplyPreservesFile:
    def test_untouched_entries_stay_byte_for_byte(self, tp, project):
        review = _write_review(project / "review.yaml", [{"msgid": "Refund", "msgstr_suggested": "Rambursare"}])

        tp.cmd_apply(review)

        expected = ORIGINAL.replace(REFUND, REFUND.replace('msgstr ""', 'msgstr "Rambursare"'))
        assert expected != ORIGINAL
        assert _po_text(project) == expected

    def test_long_new_translation_is_written_unwrapped_like_makemessages(self, tp, project):
        long_ro = "Rambursare " + "foarte lungă " * 10
        review = _write_review(project / "review.yaml", [{"msgid": "Refund", "msgstr_suggested": long_ro}])

        tp.cmd_apply(review)

        expected = ORIGINAL.replace(REFUND, REFUND.replace('msgstr ""', f'msgstr "{long_ro}"'))
        assert _po_text(project) == expected

    def test_ai_marker_and_fuzzy_removal_touch_only_their_entry(self, tp, project):
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Invoice %(number)s", "msgstr_suggested": "Factura %(number)s", "source": "ai"}],
        )

        tp.cmd_apply(review)

        new_fuzzy = """\
#. AI-generated
#: apps/billing/views.py:60
#, python-format
msgid "Invoice %(number)s"
msgstr "Factura %(number)s"
"""
        assert _po_text(project) == ORIGINAL.replace(FUZZY, new_fuzzy)


class TestApplyKeysByContext:
    def test_contextual_entry_does_not_overwrite_the_bare_msgid(self, tp, project):
        review = _write_review(
            project / "review.yaml",
            [{"msgctxt": "revenue basis", "msgid": "Cash", "msgstr_suggested": "Încasări"}],
        )

        tp.cmd_apply(review)

        new_context = CONTEXT_CASH.replace('msgstr ""', 'msgstr "Încasări"')
        assert _po_text(project) == ORIGINAL.replace(CONTEXT_CASH, new_context)

    def test_review_without_context_never_clobbers_an_existing_translation(self, tp, project):
        # A review file written before msgctxt was recorded names only the bare msgid. The bare
        # entry is already translated, so applying it must not replace "Numerar".
        review = _write_review(project / "review.yaml", [{"msgid": "Cash", "msgstr_suggested": "Încasări"}])

        tp.cmd_apply(review)

        assert _po_text(project) == ORIGINAL

    def test_obsolete_entries_are_never_targets(self, tp, project):
        review = _write_review(
            project / "review.yaml", [{"msgid": "Archived note", "msgstr_suggested": "Notă arhivată"}]
        )

        tp.cmd_apply(review)

        assert _po_text(project) == ORIGINAL


class TestApplyPlurals:
    def test_plural_forms_are_written_as_indexed_msgstrs(self, tp, project):
        forms = ["%(count)s comandă", "%(count)s comenzi", "%(count)s de comenzi"]
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "%(count)s order", "msgid_plural": "%(count)s orders", "msgstr_suggested": forms}],
        )

        tp.cmd_apply(review)

        new_plural = EMPTY_PLURAL
        for index, form in enumerate(forms):
            new_plural = new_plural.replace(f'msgstr[{index}] ""', f'msgstr[{index}] "{form}"')
        assert _po_text(project) == ORIGINAL.replace(EMPTY_PLURAL, new_plural)

    def test_single_string_for_a_plural_entry_is_rejected_without_writing(self, tp, project):
        review = _write_review(
            project / "review.yaml", [{"msgid": "%(count)s order", "msgstr_suggested": "%(count)s comandă"}]
        )

        with pytest.raises(SystemExit) as exc:
            tp.cmd_apply(review)

        assert exc.value.code == 1
        assert _po_text(project) == ORIGINAL

    def test_wrong_number_of_plural_forms_is_rejected_without_writing(self, tp, project):
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "%(count)s order", "msgstr_suggested": ["%(count)s comandă", "%(count)s comenzi"]}],
        )

        with pytest.raises(SystemExit) as exc:
            tp.cmd_apply(review)

        assert exc.value.code == 1
        assert _po_text(project) == ORIGINAL


class TestGenerateAndStats:
    def test_generate_records_context_and_plural_shape(self, tp, project):
        output = project / "review.yaml"

        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=output))

        entries = yaml.safe_load(output.read_text(encoding="utf-8"))["entries"]
        by_msgid = {(e.get("msgctxt"), e["msgid"]): e for e in entries}
        assert set(by_msgid) == {("revenue basis", "Cash"), (None, "%(count)s order"), (None, "Refund")}
        assert by_msgid[(None, "%(count)s order")]["msgid_plural"] == "%(count)s orders"
        assert by_msgid[(None, "%(count)s order")]["msgstr_suggested"] == ["", "", ""]

    def test_generate_output_applies_back_to_the_entry_it_came_from(self, tp, project):
        output = project / "review.yaml"
        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=output))
        document = yaml.safe_load(output.read_text(encoding="utf-8"))
        for entry in document["entries"]:
            if entry.get("msgctxt") == "revenue basis":
                entry["msgstr_suggested"] = "Încasări"
                entry["status"] = "approved"
        output.write_text(yaml.dump(document, allow_unicode=True), encoding="utf-8")

        tp.cmd_apply(output)

        new_context = CONTEXT_CASH.replace('msgstr ""', 'msgstr "Încasări"')
        assert _po_text(project) == ORIGINAL.replace(CONTEXT_CASH, new_context)

    def test_stats_count_a_fully_translated_plural_as_translated(self, tp, project, capsys):
        tp.cmd_stats(PO_REL)

        # Translated: long entry, template entry, bare Cash, the invoice plural. The fuzzy entry
        # is not counted without --include-fuzzy; obsolete entries are not counted at all.
        total_line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("TOTAL"))
        assert total_line.split()[1:3] == ["4", "8"]


class TestCompile:
    def test_compile_from_a_relative_po_path_runs_manage_py(self, tp, project):
        marker = project / "compiled.txt"
        manage = project / "services/platform/manage.py"
        manage.write_text(
            "import os, sys, pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text(os.getcwd() + '|' + ' '.join(sys.argv[1:]))\n",
            encoding="utf-8",
        )

        tp._compile_messages(PO_REL)

        cwd, args = marker.read_text(encoding="utf-8").split("|")
        assert Path(cwd).resolve() == manage.parent.resolve()
        assert args == "compilemessages"
