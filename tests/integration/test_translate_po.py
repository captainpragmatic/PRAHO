"""Regression tests for scripts/translate_po.py: the review-YAML round trip (generate -> apply)
and the compile step. Everything runs on a small fixture catalogue in a temp directory; the
real catalogues are never touched.

The fixture mirrors how `make i18n-extract` (makemessages --no-wrap) writes the real files:
msgid/msgstr lines are not wrapped, `#:` reference lines are, and obsolete entries sit at the
end. A whole-file rewrite through polib changes all three, whatever wrapwidth it uses.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
import yaml


def _load_module() -> ModuleType:
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "translate_po.py"
    spec = importlib.util.spec_from_file_location("translate_po", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def tp() -> ModuleType:
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
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temp repo root holding the fixture catalogue at its real relative path."""
    monkeypatch.chdir(tmp_path)
    po = tmp_path / PO_REL
    po.parent.mkdir(parents=True)
    po.write_bytes(ORIGINAL.encode("utf-8"))
    return tmp_path


def _write_review(path: Path, entries: list[dict[str, object]], *, records_context: bool = False) -> Path:
    """A review file; records_context marks it as written by a generate that records msgctxt."""
    for entry in entries:
        entry.setdefault("status", "approved")
    metadata = {"po_file": str(PO_REL)}
    if records_context:
        metadata["entry_key"] = "msgctxt+msgid"
    path.write_text(
        yaml.dump({"metadata": metadata, "entries": entries}, allow_unicode=True),
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
    @pytest.mark.parametrize("records_context", [False, True], ids=["legacy", "recorded-context"])
    def test_contextless_review_with_a_unique_contextual_match(
        self, tp: ModuleType, project: Path, records_context: bool
    ) -> None:
        obsolete_cash = '#~ msgid "Cash"\n#~ msgstr "Numerar"\n'
        catalogue = _catalogue(CONTEXT_CASH, obsolete_cash)
        (project / PO_REL).write_bytes(catalogue.encode("utf-8"))
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Cash", "msgstr_suggested": "Încasări"}],
            records_context=records_context,
        )

        tp.cmd_apply(review)

        new_context = CONTEXT_CASH.replace('msgstr ""', 'msgstr "Încasări"')
        expected = catalogue if records_context else catalogue.replace(CONTEXT_CASH, new_context)
        assert _po_text(project) == expected

    def test_legacy_review_refuses_an_ambiguous_msgid_even_when_both_entries_are_untranslated(
        self, tp: ModuleType, project: Path
    ) -> None:
        empty_bare_cash = BARE_CASH.replace('msgstr "Numerar"', 'msgstr ""')
        catalogue = _catalogue(CONTEXT_CASH, empty_bare_cash)
        (project / PO_REL).write_bytes(catalogue.encode("utf-8"))
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Cash", "msgstr_suggested": "Încasări", "overwrite": True}],
        )

        tp.cmd_apply(review, overwrite=True)

        assert _po_text(project) == catalogue

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


class TestEntryBoundaries:
    """gettext does not need blank lines between entries, and allows them inside a field."""

    def _install(self, project: Path, text: str) -> None:
        (project / PO_REL).write_bytes(text.encode("utf-8"))

    def test_header_without_trailing_blank_line_keeps_header_and_first_entry(self, tp, project):
        text = HEADER + REFUND + "\n" + BARE_CASH
        self._install(project, text)
        review = _write_review(project / "review.yaml", [{"msgid": "Refund", "msgstr_suggested": "Rambursare"}])

        tp.cmd_apply(review)

        assert _po_text(project) == HEADER + REFUND.replace('msgstr ""', 'msgstr "Rambursare"') + "\n" + BARE_CASH

    def test_blank_line_inside_a_multiline_msgstr_is_replaced_with_the_field(self, tp, project):
        target = """\
#: apps/billing/views.py:70
#, fuzzy
msgid "Long notice"
msgstr ""
"Prima parte "

"a doua parte"
"""
        text = HEADER + "\n" + target + REFUND
        self._install(project, text)
        review = _write_review(project / "review.yaml", [{"msgid": "Long notice", "msgstr_suggested": "Notificare"}])

        tp.cmd_apply(review)

        new_target = """\
#: apps/billing/views.py:70
msgid "Long notice"
msgstr "Notificare"
"""
        assert _po_text(project) == HEADER + "\n" + new_target + REFUND

    def test_target_packed_between_header_and_obsolete_block(self, tp, project):
        text = HEADER + REFUND + OBSOLETE
        self._install(project, text)
        review = _write_review(project / "review.yaml", [{"msgid": "Refund", "msgstr_suggested": "Rambursare"}])

        tp.cmd_apply(review)

        assert _po_text(project) == HEADER + REFUND.replace('msgstr ""', 'msgstr "Rambursare"') + OBSOLETE

    def test_packed_context_and_multiline_keywords_keep_their_source(
        self, tp: ModuleType, project: Path
    ) -> None:
        target = (
            '#. Billing notice\n'
            '#: apps/billing/views.py:70\n'
            '#, fuzzy\n'
            'msgctxt ""\n'
            '"billing "\n\n'
            '"notice"\n'
            'msgid ""\n'
            '"Long "\n\n'
            '"notice"\n'
            'msgstr ""\n'
            '"Prima parte "\n\n'
            '"a doua parte"\n'
        )
        text = HEADER + target + REFUND + OBSOLETE
        self._install(project, text)
        review = _write_review(
            project / "review.yaml",
            [
                {"msgctxt": "billing notice", "msgid": "Long notice", "msgstr_suggested": "Notificare"},
                {"msgid": "Refund", "msgstr_suggested": "Rambursare"},
            ],
        )

        tp.cmd_apply(review)

        expected_target = target[:target.index('msgstr ""')].replace('#, fuzzy\n', '') + 'msgstr "Notificare"\n'
        expected_refund = REFUND.replace('msgstr ""', 'msgstr "Rambursare"')
        assert _po_text(project) == HEADER + expected_target + expected_refund + OBSOLETE


INCOMPLETE_PLURAL = """\
#: apps/billing/views.py:80
#, python-format
msgid "%(count)s domain"
msgid_plural "%(count)s domains"
msgstr[0] "%(count)s domeniu"
msgstr[1] "%(count)s domenii"
"""


class TestIncompletePlurals:
    """With nplurals=3, missing and explicitly empty msgstr[2] both need translation."""

    @pytest.fixture(params=["", 'msgstr[2] ""\n'], ids=["missing", "empty"])
    def incomplete(self, project: Path, request: pytest.FixtureRequest) -> Path:
        suffix: str = request.param
        (project / PO_REL).write_bytes(_catalogue(REFUND, INCOMPLETE_PLURAL + suffix).encode("utf-8"))
        return project

    def test_generate_lists_a_plural_missing_a_form(self, tp, incomplete):
        output = incomplete / "review.yaml"

        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=output))

        msgids = [e["msgid"] for e in yaml.safe_load(output.read_text(encoding="utf-8"))["entries"]]
        assert "%(count)s domain" in msgids

    def test_generate_preserves_existing_forms_of_a_partially_translated_plural(
        self, tp: ModuleType, incomplete: Path
    ) -> None:
        output = incomplete / "review.yaml"

        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=output))

        entries = yaml.safe_load(output.read_text(encoding="utf-8"))["entries"]
        plural = next(entry for entry in entries if entry["msgid"] == "%(count)s domain")
        assert plural["msgstr_suggested"] == ["%(count)s domeniu", "%(count)s domenii", ""]

    def test_stats_do_not_count_a_plural_missing_a_form(self, tp, incomplete, capsys):
        tp.cmd_stats(PO_REL)

        total_line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("TOTAL"))
        assert total_line.split()[1:3] == ["0", "2"]

    @pytest.fixture()
    def reviewed_plural(self, tp: ModuleType, incomplete: Path) -> Path:
        review = incomplete / "review.yaml"
        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=review))
        document = cast("dict[str, object]", yaml.safe_load(review.read_text(encoding="utf-8")))
        entries = cast("list[dict[str, object]]", document["entries"])
        plural = next(entry for entry in entries if entry["msgid"] == "%(count)s domain")
        forms = cast("list[str]", plural["msgstr_suggested"])
        assert forms == ["%(count)s domeniu", "%(count)s domenii", ""]
        forms[2] = "%(count)s de domenii"
        plural["status"] = "approved"
        review.write_text(yaml.dump(document, allow_unicode=True), encoding="utf-8")
        return review

    @pytest.fixture(params=[0, 1], ids=["form-0", "form-1"])
    def changed_plural(self, incomplete: Path, reviewed_plural: Path, request: pytest.FixtureRequest) -> bytes:
        # Depending on reviewed_plural ensures this edit happens after generate and review.
        index = cast("int", request.param)
        original_form = ["%(count)s domeniu", "%(count)s domenii"][index]
        po = incomplete / PO_REL
        changed = po.read_bytes().replace(
            f'msgstr[{index}] "{original_form}"'.encode(),
            f'msgstr[{index}] "%(count)s traducere nouă"'.encode(),
        )
        po.write_bytes(changed)
        return changed

    def test_stale_partial_plural_is_skipped_without_overwrite(
        self,
        tp: ModuleType,
        incomplete: Path,
        reviewed_plural: Path,
        changed_plural: bytes,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        tp.cmd_apply(reviewed_plural)

        assert (incomplete / PO_REL).read_bytes() == changed_plural
        assert "Already translated, not overwriting without --overwrite or overwrite: true" in caplog.text

    @pytest.mark.parametrize("overwrite", [False, True], ids=["per-entry", "cli"])
    def test_stale_partial_plural_applies_with_overwrite(
        self,
        tp: ModuleType,
        incomplete: Path,
        reviewed_plural: Path,
        changed_plural: bytes,
        overwrite: bool,
    ) -> None:
        if not overwrite:
            document = cast("dict[str, object]", yaml.safe_load(reviewed_plural.read_text(encoding="utf-8")))
            entries = cast("list[dict[str, object]]", document["entries"])
            plural = next(entry for entry in entries if entry["msgid"] == "%(count)s domain")
            plural["overwrite"] = True
            reviewed_plural.write_text(yaml.dump(document, allow_unicode=True), encoding="utf-8")

        assert (incomplete / PO_REL).read_bytes() == changed_plural
        tp.cmd_apply(reviewed_plural, overwrite=overwrite)

        repaired = INCOMPLETE_PLURAL + 'msgstr[2] "%(count)s de domenii"\n'
        assert (incomplete / PO_REL).read_bytes() == _catalogue(REFUND, repaired).encode()

    def test_unchanged_partial_plural_fills_missing_form(
        self, tp: ModuleType, incomplete: Path, reviewed_plural: Path
    ) -> None:
        tp.cmd_apply(reviewed_plural)

        repaired = INCOMPLETE_PLURAL + 'msgstr[2] "%(count)s de domenii"\n'
        assert (incomplete / PO_REL).read_bytes() == _catalogue(REFUND, repaired).encode()

    def test_apply_repairs_a_plural_missing_a_form(self, tp, incomplete):
        forms = ["%(count)s domeniu", "%(count)s domenii", "%(count)s de domenii"]
        review = _write_review(
            incomplete / "review.yaml",
            [{"msgid": "%(count)s domain", "msgid_plural": "%(count)s domains", "msgstr_suggested": forms}],
        )

        tp.cmd_apply(review)

        repaired = INCOMPLETE_PLURAL + 'msgstr[2] "%(count)s de domenii"\n'
        assert _po_text(incomplete) == _catalogue(REFUND, repaired)


class TestOverwrite:
    def test_per_entry_overwrite_corrects_an_existing_translation(self, tp, project):
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Cash", "msgstr_suggested": "Numerar (bani gheață)", "overwrite": True}],
            records_context=True,
        )

        tp.cmd_apply(review)

        new_cash = BARE_CASH.replace('msgstr "Numerar"', 'msgstr "Numerar (bani gheață)"')
        assert _po_text(project) == ORIGINAL.replace(BARE_CASH, new_cash)

    def test_overwrite_option_corrects_an_existing_translation(self, tp, project):
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Cash", "msgstr_suggested": "Numerar (bani gheață)"}],
            records_context=True,
        )

        tp.cmd_apply(review, overwrite=True)

        new_cash = BARE_CASH.replace('msgstr "Numerar"', 'msgstr "Numerar (bani gheață)"')
        assert _po_text(project) == ORIGINAL.replace(BARE_CASH, new_cash)

    def test_review_without_recorded_context_is_refused_for_an_ambiguous_msgid_even_with_overwrite(
        self, tp, project
    ):
        # Written before msgctxt was recorded: "Cash" may have been generated from the
        # "revenue basis" entry, so it must not land on the bare one.
        review = _write_review(
            project / "review.yaml", [{"msgid": "Cash", "msgstr_suggested": "Încasări", "overwrite": True}]
        )

        tp.cmd_apply(review, overwrite=True)

        assert _po_text(project) == ORIGINAL

    def test_generate_marks_its_review_file_as_recording_context(self, tp, project):
        output = project / "review.yaml"

        tp.cmd_generate(tp.GenerateConfig(po_file=PO_REL, output=output))

        assert yaml.safe_load(output.read_text(encoding="utf-8"))["metadata"]["entry_key"] == "msgctxt+msgid"

    @pytest.mark.parametrize("overwrite_value", [None, False, "true"])
    def test_translated_entry_is_skipped_without_an_explicit_boolean_override(
        self, tp: ModuleType, project: Path, overwrite_value: object
    ) -> None:
        entry: dict[str, object] = {"msgid": "Cash", "msgstr_suggested": "Bani"}
        if overwrite_value is not None:
            entry["overwrite"] = overwrite_value
        review = _write_review(project / "review.yaml", [entry], records_context=True)

        tp.cmd_apply(review)

        assert _po_text(project) == ORIGINAL

    @pytest.mark.parametrize(
        "msgctxt,msgid",
        [("unknown", "Cash"), ("revenue basis", "cash"), ("", "Cash")],
    )
    def test_overwrite_still_requires_an_exact_context_and_msgid(
        self, tp: ModuleType, project: Path, msgctxt: str, msgid: str
    ) -> None:
        review = _write_review(
            project / "review.yaml",
            [{"msgctxt": msgctxt, "msgid": msgid, "msgstr_suggested": "Bani", "overwrite": True}],
            records_context=True,
        )

        tp.cmd_apply(review, overwrite=True)

        assert _po_text(project) == ORIGINAL

    @pytest.mark.parametrize("msgctxt,msgid", [(["revenue basis"], "Cash"), (None, ["Cash"])])
    def test_invalid_key_types_are_rejected_before_overwrite(
        self, tp: ModuleType, project: Path, msgctxt: object, msgid: object
    ) -> None:
        review = _write_review(
            project / "review.yaml",
            [{"msgctxt": msgctxt, "msgid": msgid, "msgstr_suggested": "Bani", "overwrite": True}],
            records_context=True,
        )

        with pytest.raises(SystemExit) as exc:
            tp.cmd_apply(review)

        assert exc.value.code == 1
        assert _po_text(project) == ORIGINAL

    def test_overwrite_cli_flag_reaches_apply(
        self, tp: ModuleType, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "Cash", "msgstr_suggested": "Bani"}],
            records_context=True,
        )
        monkeypatch.setattr(sys, "argv", ["translate_po.py", "apply", str(review), "--overwrite"])

        tp.main()

        assert _po_text(project) == ORIGINAL.replace(BARE_CASH, BARE_CASH.replace("Numerar", "Bani"))

    def test_overwrite_still_validates_placeholders(self, tp: ModuleType, project: Path) -> None:
        review = _write_review(
            project / "review.yaml",
            [{"msgid": "%(count)s invoice", "msgstr_suggested": ["factură", "facturi", "de facturi"]}],
        )

        with pytest.raises(SystemExit) as exc:
            tp.cmd_apply(review, overwrite=True)

        assert exc.value.code == 1
        assert _po_text(project) == ORIGINAL


class TestFuzzyOnItsOwnFlagLine:
    @pytest.mark.parametrize(
        "fuzzy_flags,remaining_flags",
        [
            ("#, fuzzy\n", ""),
            ("#, fuzzy, no-wrap\n", "#, no-wrap\n"),
            ("#, fuzzy, no-wrap\n#, fuzzy\n", "#, no-wrap\n"),
        ],
    )
    def test_fuzzy_is_removed_from_whichever_flag_line_holds_it(
        self, tp: ModuleType, project: Path, fuzzy_flags: str, remaining_flags: str
    ) -> None:
        split_flags = (
            "#: apps/billing/views.py:90\n"
            "#, python-format\n"
            + fuzzy_flags
            + 'msgid "Proforma %(number)s"\n'
            'msgstr "Factura %(number)s"\n'
        )
        (project / PO_REL).write_bytes(_catalogue(REFUND, split_flags).encode("utf-8"))
        review = _write_review(
            project / "review.yaml", [{"msgid": "Proforma %(number)s", "msgstr_suggested": "Proformă %(number)s"}]
        )

        tp.cmd_apply(review)

        expected = (
            "#: apps/billing/views.py:90\n"
            "#, python-format\n"
            + remaining_flags
            + 'msgid "Proforma %(number)s"\n'
            'msgstr "Proformă %(number)s"\n'
        )
        assert _po_text(project) == _catalogue(REFUND, expected)


class TestAtomicWrite:
    def _review(self, project: Path) -> Path:
        return _write_review(project / "review.yaml", [{"msgid": "Refund", "msgstr_suggested": "Rambursare"}])

    def test_a_failed_flush_leaves_the_catalogue_whole_and_no_temp_files(self, tp, project, monkeypatch):
        review = self._review(project)
        before = sorted(p.name for p in (project / PO_REL).parent.iterdir())

        def failing_fsync(fd: int) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(os, "fsync", failing_fsync)

        with pytest.raises(OSError, match="disk full"):
            tp.cmd_apply(review)

        assert _po_text(project) == ORIGINAL
        assert sorted(p.name for p in (project / PO_REL).parent.iterdir()) == before

    def test_a_reader_holding_the_old_catalogue_open_keeps_a_complete_copy(self, tp, project):
        review = self._review(project)

        with (project / PO_REL).open("rb") as reader:
            tp.cmd_apply(review)
            assert reader.read().decode("utf-8") == ORIGINAL

        assert "Rambursare" in _po_text(project)

    def test_file_mode_is_preserved(self, tp, project):
        po = project / PO_REL
        po.chmod(0o640)

        tp.cmd_apply(self._review(project))

        assert po.stat().st_mode & 0o777 == 0o640

    def test_failed_replace_preserves_the_catalogue_and_cleans_up(
        self, tp: ModuleType, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        po = project / PO_REL
        before = sorted(path.name for path in po.parent.iterdir())

        def failing_replace(source: Path, destination: Path) -> None:
            assert source.parent == destination.parent == po.parent.resolve()
            assert destination.read_bytes() == ORIGINAL.encode("utf-8")
            raise OSError("replace failed")

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(OSError, match="replace failed"):
            tp.cmd_apply(self._review(project))

        assert _po_text(project) == ORIGINAL
        assert sorted(path.name for path in po.parent.iterdir()) == before

    def test_temp_catalogue_is_complete_and_synced_before_replace(
        self, tp: ModuleType, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        po = project / PO_REL
        expected = ORIGINAL.replace(REFUND, REFUND.replace('msgstr ""', 'msgstr "Rambursare"'))
        events: list[str] = []
        real_fsync = os.fsync
        real_replace = os.replace

        def observing_fsync(fd: int) -> None:
            # Reading through a separate descriptor proves the buffered write was flushed.
            temps = list(po.parent.glob(".django.po.*.tmp"))
            assert len(temps) == 1
            assert temps[0].read_bytes() == expected.encode("utf-8")
            assert po.read_bytes() == ORIGINAL.encode("utf-8")
            real_fsync(fd)
            events.append("fsync")

        def observing_replace(source: Path, destination: Path) -> None:
            assert source.parent == destination.parent == po.parent.resolve()
            assert source != destination
            assert source.read_bytes() == expected.encode("utf-8")
            assert destination.read_bytes() == ORIGINAL.encode("utf-8")
            assert events == ["fsync"]
            real_replace(source, destination)
            events.append("replace")

        monkeypatch.setattr(os, "fsync", observing_fsync)
        monkeypatch.setattr(os, "replace", observing_replace)

        tp.cmd_apply(self._review(project))

        assert events == ["fsync", "replace"]
        assert _po_text(project) == expected
        assert sorted(path.name for path in po.parent.iterdir()) == ["django.po"]
