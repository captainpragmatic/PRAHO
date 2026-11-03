"""Real gettext/extraction fixtures for the read-only Romanian catalog gate."""

from __future__ import annotations

import ast
import gettext
import importlib.util
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import polib
import pytest

ROOT = Path(__file__).resolve().parents[2]
TREES = ("services/platform", "services/portal", "shared/ui")
CATALOG = Path("locale/ro/LC_MESSAGES/django.po")
PLURAL = "nplurals=3; plural=(n==1?0:(((n%100>19)||((n%100==0)&&(n!=0)))?2:1));"


@pytest.fixture()
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location("translate_check_test", ROOT / "scripts/translate_po.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # These fixtures need gettext on PATH, never the operator's deployment environment.
    # Keep a future failing subprocess assertion from printing credentials in traceback args.
    monkeypatch.setattr(module.os, "environ", {"PATH": module.os.environ.get("PATH", "")})
    return module


def compile_po(path: Path) -> None:
    msgfmt = shutil.which("msgfmt")
    assert msgfmt is not None, "Install GNU gettext before running translation fixtures"
    subprocess.run(  # noqa: S603 -- Fixed gettext executable and temporary fixture paths; no shell.
        [msgfmt, "--check-format", "-o", str(path.with_suffix(".mo")), str(path)], check=True
    )


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    """Use the production extraction recipe, with minimal independent Django settings."""
    makefile = (ROOT / "Makefile").read_text()
    recipe = makefile.split("i18n-extract:\n", 1)[1].split("\ni18n-compile:", 1)[0]
    (tmp_path / "Makefile").write_text(
        f"VENV_DIR := {Path(sys.prefix)}\ni18n-extract:\n{recipe}\ntest-i18n-guards:\n\t@test ! -f guard-failure\n"
    )
    # The production recipe prepends PWD to VENV_DIR, so give it a local venv link.
    venv = f".venv-{sys.platform}"
    (tmp_path / venv).symlink_to(sys.prefix, target_is_directory=True)
    (tmp_path / "Makefile").write_text((tmp_path / "Makefile").read_text().replace(str(Path(sys.prefix)), venv))
    for tree in TREES:
        base = tmp_path / tree
        po = base / CATALOG
        po.parent.mkdir(parents=True)
        catalog = polib.POFile()
        catalog.metadata = {"Content-Type": "text/plain; charset=UTF-8", "Language": "ro", "Plural-Forms": PLURAL}
        catalog.append(polib.POEntry(msgid="Invoice", msgstr="Factură", occurrences=[("messages.html", "1")]))
        catalog.save(str(po))
        compile_po(po)
        (base / "messages.html").write_text('{% load i18n %}{% trans "Invoice" %}')
        if tree.startswith("services"):
            (base / "config/settings").mkdir(parents=True)
            (base / "config/__init__.py").touch()
            (base / "config/settings/__init__.py").touch()
            (base / "config/settings/dev.py").write_text(
                "from pathlib import Path\nBASE_DIR = Path(__file__).resolve().parents[2]\n"
                "SECRET_KEY = 'fixture'\nINSTALLED_APPS = []\nUSE_I18N = True\n"
                "LOCALE_PATHS = [BASE_DIR / 'locale']\n"
                "MEDIA_ROOT = BASE_DIR / 'media'\nSTATIC_ROOT = BASE_DIR / 'staticfiles'\n"
            )
            (base / "manage.py").write_text(
                "from django.core.management import execute_from_command_line\nexecute_from_command_line()\n"
            )
    return tmp_path


@pytest.fixture()
def real_markup_project(project: Path) -> Path:
    """Use the repository's actual markup guard without unrelated template fixtures."""
    guard = Path("tests/integration/test_translation_catalog_markup.py")
    (project / guard).parent.mkdir(parents=True)
    (project / guard).write_bytes((ROOT / guard).read_bytes())
    (project / "pytest.ini").write_text("[pytest]\naddopts =\n")
    makefile = project / "Makefile"
    makefile.write_text(
        makefile.read_text().replace(
            "\t@test ! -f guard-failure\n",
            "\t@$(VENV_DIR)/bin/python -m pytest -c pytest.ini --rootdir=. --confcutdir=. "
            "-o addopts= --no-cov -p no:cacheprovider "
            f"-k test_no_translation_adds_markup {guard} -q\n",
        )
    )
    return project


def english_catalog(project: Path, relative: str, *, unsafe: bool = False) -> Path:
    path = project / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    po = polib.POFile()
    po.metadata = {
        "Content-Type": "text/plain; charset=UTF-8",
        "Language": "en",
        "Plural-Forms": "nplurals=2; plural=(n != 1);",
    }
    po.append(polib.POEntry(msgid="Invoice", msgstr="<b>Invoice</b>" if unsafe else ""))
    po.append(polib.POEntry(msgid="File", msgid_plural="Files", msgstr_plural={0: "File", 1: ""}))
    po.save(str(path))
    return path


def files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def change_po(project: Path, change: Callable[[polib.POFile], None], *, recompile: bool = False) -> Path:
    path = project / TREES[0] / CATALOG
    po = polib.pofile(str(path))
    change(po)
    po.save(str(path))
    if recompile:
        compile_po(path)
    return path


def rejects(checker, project: Path, message: str) -> str:
    before = files(project)
    with pytest.raises(checker.CatalogCheckError, match=message) as error:
        checker.check_catalogs(project)
    assert files(project) == before
    return str(error.value)


def test_clean_catalogs_are_read_only(checker, project: Path, monkeypatch) -> None:
    before = files(project)
    monkeypatch.chdir(project.parent)
    checker.check_catalogs(project)
    assert files(project) == before


@pytest.mark.parametrize(
    "relative",
    [
        "services/platform/locale/en/LC_MESSAGES/django.po",
        "extras/locale/en/LC_MESSAGES/django.po",
        ".catalog-fixtures/locale/en/LC_MESSAGES/django.po",
        "services/platform/media/locale/en/LC_MESSAGES/django.po",
    ],
)
def test_snapshot_preserves_the_real_markup_guards_catalog_scope(
    checker, real_markup_project: Path, relative: str
) -> None:
    english_catalog(real_markup_project, relative, unsafe=True)
    before = files(real_markup_project)
    env = dict(checker.os.environ, PYTHONDONTWRITEBYTECODE="1", PRAHO_SKIP_DOTENV="1")
    # Establish that this is a real English markup violation, rather than a broken fixture.
    with pytest.raises(checker.CatalogCheckError, match="guards failed") as original_error:
        checker._run_catalog_step(["make", "test-i18n-guards"], real_markup_project, env, "guards")
    assert relative in str(original_error.value)
    assert "Invoice" in str(original_error.value) and "tags" in str(original_error.value)
    assert files(real_markup_project) == before
    error = rejects(checker, real_markup_project, "guards failed")
    assert relative in error and "Invoice" in error and "tags" in error


def test_other_languages_do_not_require_complete_translations_or_compiled_catalogs(
    checker, real_markup_project: Path
) -> None:
    path = english_catalog(real_markup_project, "services/platform/locale/en/LC_MESSAGES/django.po")
    assert not path.with_suffix(".mo").exists()
    assert polib.pofile(str(path)).untranslated_entries()
    before = files(real_markup_project)
    checker.check_catalogs(real_markup_project)
    assert files(real_markup_project) == before


@pytest.mark.parametrize("directory", [".venv-extra", "node_modules/package"])
def test_guard_catalog_exclusions_are_not_captured(checker, real_markup_project: Path, directory: str) -> None:
    relative = f"{directory}/locale/en/LC_MESSAGES/django.po"
    english_catalog(real_markup_project, relative, unsafe=True)
    assert Path(relative) not in checker._capture_catalog_inputs(real_markup_project)
    before = files(real_markup_project)
    checker.check_catalogs(real_markup_project)
    assert files(real_markup_project) == before


@pytest.mark.parametrize("mutation", ["modify", "remove", "add"])
def test_other_language_inputs_are_frozen_and_rechecked(
    checker, real_markup_project: Path, monkeypatch, mutation: str
) -> None:
    relative = "services/platform/locale/en/LC_MESSAGES/django.po"
    path = english_catalog(real_markup_project, relative)
    captured = path.read_bytes()
    target = real_markup_project / "english-input.po"
    path.rename(target)
    path.symlink_to(target)
    changed = "extras/locale/fr/LC_MESSAGES/django.po" if mutation == "add" else relative
    run = subprocess.run

    def mutate_during_guards(args, **kwargs):
        if "test-i18n-guards" in args:
            staged = Path(kwargs["cwd"]) / relative
            assert staged.is_file() and not staged.is_symlink()
            assert staged.read_bytes() == captured
            if mutation == "modify":
                english_catalog(real_markup_project, relative, unsafe=True)
            elif mutation == "remove":
                path.unlink()
            else:
                english_catalog(real_markup_project, changed, unsafe=True)
        result = run(args, **kwargs)
        if "test-i18n-guards" in args:
            assert result.returncode == 0, result.stdout + result.stderr
        return result

    monkeypatch.setattr(subprocess, "run", mutate_during_guards)
    with pytest.raises(checker.CatalogCheckError, match="inputs changed") as error:
        checker.check_catalogs(real_markup_project)
    assert changed in str(error.value)


@pytest.mark.parametrize("defect", ["untranslated", "fuzzy", "incomplete plural", "duplicate"])
def test_original_defects_are_rejected_before_extraction(checker, project: Path, defect: str) -> None:
    def corrupt(po):
        if defect == "untranslated":
            po[0].msgstr = ""
        elif defect == "fuzzy":
            po[0].flags.append("fuzzy")
        elif defect == "duplicate":
            po.append(polib.POEntry(msgid="Invoice", msgstr="Altă factură"))
        else:
            po[0].msgid_plural = "Invoices"
            po[0].msgstr = ""
            po[0].msgstr_plural = {0: "Factură", 1: "Facturi"}

    change_po(project, corrupt)
    error = rejects(checker, project, defect)
    assert "services/platform" in error and "Invoice" in error and "messages.html" in error


@pytest.mark.parametrize("defect", ["missing", "stale", "extra", "corrupt", "Plural-Forms"])
def test_compiled_runtime_content_must_match(checker, project: Path, defect: str) -> None:
    path = project / TREES[0] / CATALOG
    if defect == "missing":
        path.with_suffix(".mo").unlink()
    elif defect == "corrupt":
        path.with_suffix(".mo").write_bytes(b"bad mo")
    else:
        po = polib.pofile(str(path))
        if defect == "stale":
            po[0].msgstr = "Învechit"
        elif defect == "extra":
            po.append(polib.POEntry(msgid="Extra", msgstr="Suplimentar"))
        else:
            po.metadata["Plural-Forms"] = "nplurals=3; plural=(n==1?0:1);"
        po.save_as_mofile(str(path.with_suffix(".mo")))
    rejects(checker, project, defect)


def test_corrupt_original_mo_is_rejected_before_any_compilation(checker, project: Path, monkeypatch) -> None:
    (project / TREES[1] / CATALOG.with_suffix(".mo")).write_bytes(b"corrupt original")

    def forbid_compilation(*args, **kwargs):
        raise AssertionError("original catalog validation must precede subprocess compilation")

    monkeypatch.setattr(subprocess, "run", forbid_compilation)
    assert "services/portal" in rejects(checker, project, "corrupt compiled catalog")


def test_contexts_are_distinct_but_compiled_context_is_checked(checker, project: Path) -> None:
    path = change_po(
        project,
        lambda po: po.append(polib.POEntry(msgctxt="billing", msgid="Invoice", msgstr="Facturare")),
        recompile=True,
    )
    (path.parents[3] / "messages.html").write_text(
        '{% load i18n %}{% trans "Invoice" %}{% trans "Invoice" context "billing" %}'
    )
    checker.check_catalogs(project)
    po = polib.pofile(str(path))
    po[1].msgstr = "Greșit"
    po.save_as_mofile(str(path.with_suffix(".mo")))
    assert "billing" in rejects(checker, project, "stale")


def test_obsolete_entries_ignored_but_revival_is_drift(checker, project: Path) -> None:
    change_po(
        project,
        lambda po: po.append(polib.POEntry(msgid="Revived", msgstr="Restabilit", obsolete=True)),
        recompile=True,
    )
    checker.check_catalogs(project)
    (project / TREES[0] / "new.py").write_text('from django.utils.translation import gettext as _\n_("Revived")\n')
    assert "Revived" in rejects(checker, project, "added")


@pytest.mark.parametrize(
    "source,target",
    [
        ("Amount %(amount)08.2f", "Sumă %(other)08.2f"),
        ("Width %*.*f", "Lățime %f"),
        ("Value {value:.2f}", "Valoare {other:.2f}"),
    ],
)
def test_format_errors_include_width_and_precision(checker, project: Path, source: str, target: str) -> None:
    def corrupt(po):
        po[0].msgid, po[0].msgstr = source, target
        po[0].flags = ["python-format"] if "%" in source else ["python-brace-format"]

    change_po(project, corrupt)
    rejects(checker, project, "[Pp]laceholder|format")


def test_romanian_plural_rendering(checker, project: Path) -> None:
    def plural(po):
        po[0].msgid = "%(count)d invoice"
        po[0].msgid_plural = "%(count)d invoices"
        po[0].msgstr = ""
        po[0].msgstr_plural = {0: "%(count)d factură", 1: "%(count)d facturi", 2: "%(count)d de facturi"}
        po[0].flags = ["python-format"]

    path = change_po(project, plural, recompile=True)
    (project / TREES[0] / "messages.html").unlink()
    (project / TREES[0] / "plural.py").write_text(
        'from django.utils.translation import ngettext\nngettext("%(count)d invoice", "%(count)d invoices", 2)\n'
    )
    checker.check_catalogs(project)
    with path.with_suffix(".mo").open("rb") as handle:
        runtime = gettext.GNUTranslations(handle)
    for count, expected in [
        (0, "facturi"),
        (1, "factură"),
        (2, "facturi"),
        (19, "facturi"),
        (20, "de facturi"),
        (100, "de facturi"),
        (101, "facturi"),
    ]:
        assert (
            runtime.ngettext("%(count)d invoice", "%(count)d invoices", count) % {"count": count}
            == f"{count} {expected}"
        )


@pytest.mark.parametrize(
    "tree,extension",
    [("services/platform", "py"), ("services/portal", "txt"), ("shared/ui", "html"), ("shared/ui", "txt")],
)
def test_new_untracked_source_is_detected(checker, project: Path, tree: str, extension: str) -> None:
    source = (
        'from django.utils.translation import gettext as _\n_("Untracked message")'
        if extension == "py"
        else '{% load i18n %}{% trans "Untracked message" %}'
    )
    (project / tree / f"untracked.{extension}").write_text(source)
    error = rejects(checker, project, "added")
    assert "Untracked message" in error and f"untracked.{extension}" in error


def test_discovery_exclusions_and_metadata_noise(checker, project: Path, tmp_path: Path) -> None:
    base = project / TREES[0]
    for dirname in (".hidden", "CVS", "media", "staticfiles"):
        (base / dirname).mkdir()
        (base / dirname / "ignored.html").write_text('{% trans "Ignored" %}')
    outside = project / "outside"
    outside.mkdir()
    (outside / "ignored.html").write_text('{% trans "Ignored symlink" %}')
    (base / "linked").symlink_to(outside, target_is_directory=True)
    (project / "shared/ui/not-extracted.py").write_text('_("Shared Python is excluded")')
    change_po(project, lambda po: po.metadata.update({"POT-Creation-Date": "2000-01-01 00:00+0000"}))
    checker.check_catalogs(project)


@pytest.mark.parametrize("defect", ["removed", "changed plural", "changed translation"])
def test_semantic_extraction_drift(checker, project: Path, defect: str, monkeypatch) -> None:
    if defect == "removed":
        (project / TREES[0] / "messages.html").write_text('{% load i18n %}{% trans "Replacement" %}')
    else:
        run = subprocess.run

        def alter(args, **kwargs):
            result = run(args, **kwargs)
            if "i18n-extract" in args:
                staged = Path(kwargs["cwd"])

                def change(po):
                    if defect == "changed plural":
                        po[0].msgid_plural = "New invoices"
                    else:
                        po[0].msgstr = "Schimbat"

                change_po(staged, change)
            return result

        monkeypatch.setattr(subprocess, "run", alter)
    rejects(checker, project, defect)


@pytest.mark.parametrize("original_format_flag", [False, True], ids=["flag-added", "flag-removed"])
@pytest.mark.parametrize("fuzzy", [False, True], ids=["format-only", "fuzzy-rejected"])
def test_gettext_format_inference_variation_is_not_catalog_drift(
    checker, project: Path, monkeypatch, original_format_flag: bool, fuzzy: bool
) -> None:
    source = "Your data deletion request has been submitted. This action cannot be undone. Request ID: {}"

    def prepare(po: polib.POFile) -> None:
        entry = po[0]
        entry.msgid = source
        entry.msgstr = (
            "Cererea dvs. de ștergere a datelor a fost trimisă. Această acțiune nu poate fi anulată. ID cerere: {}"
        )
        entry.flags = ["python-brace-format"] if original_format_flag else []
        entry.occurrences = [("messages.py", "2")]

    change_po(project, prepare, recompile=True)
    (project / TREES[0] / "messages.html").unlink()
    (project / TREES[0] / "messages.py").write_text(
        f'from django.utils.translation import gettext as _\n_("{source}")\n'
    )
    run = subprocess.run

    def vary_gettext_inference(args, **kwargs):
        result = run(args, **kwargs)
        if "i18n-extract" in args:

            def change(po):
                entry = po.find(source)
                assert entry is not None
                entry.flags = [] if original_format_flag else ["python-brace-format"]
                if fuzzy:
                    entry.flags.append("fuzzy")

            change_po(Path(kwargs["cwd"]), change)
        return result

    monkeypatch.setattr(subprocess, "run", vary_gettext_inference)
    if fuzzy:
        error = rejects(checker, project, "fuzzy")
        assert source in error and "messages.py:2" in error
    else:
        before = files(project)
        checker.check_catalogs(project)
        assert files(project) == before


def test_non_format_extraction_flags_still_require_review(checker, project: Path, monkeypatch) -> None:
    run = subprocess.run

    def add_non_format_flag(args, **kwargs):
        result = run(args, **kwargs)
        if "i18n-extract" in args:
            change_po(Path(kwargs["cwd"]), lambda po: po[0].flags.append("no-wrap"))
        return result

    monkeypatch.setattr(subprocess, "run", add_non_format_flag)
    assert "no-wrap" in rejects(checker, project, "changed extraction flags")


def test_missing_gettext_is_actionable(checker, project: Path, monkeypatch) -> None:
    which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "msgfmt" else which(name))
    rejects(checker, project, "msgfmt.*gettext")


@pytest.mark.parametrize("step", ["extraction", "guards"])
def test_subprocess_failures_are_not_ignored(checker, project: Path, step: str) -> None:
    with (project / "Makefile").open("a") as handle:
        handle.write(
            f"\n{'i18n-extract' if step == 'extraction' else 'test-i18n-guards'}:\n\t@echo fixture-failure >&2\n\t@exit 1\n"
        )
    assert "fixture-failure" in rejects(checker, project, step)


def test_input_changes_during_check_are_rejected(checker, project: Path, monkeypatch) -> None:
    run = subprocess.run

    def mutate(args, **kwargs):
        result = run(args, **kwargs)
        if "i18n-extract" in args:
            (project / TREES[0] / "late.txt").write_text("late input")
        return result

    monkeypatch.setattr(subprocess, "run", mutate)
    with pytest.raises(checker.CatalogCheckError, match=r"inputs changed.*late\.txt"):
        checker.check_catalogs(project)


def test_missing_and_malformed_po_are_rejected(checker, project: Path) -> None:
    path = project / TREES[0] / CATALOG
    path.write_text('msgid "broken\n')
    rejects(checker, project, "malformed")
    path.unlink()
    rejects(checker, project, "missing")


@pytest.mark.parametrize("tree", TREES)
def test_removing_the_last_source_message_is_drift(checker, project: Path, tree: str) -> None:
    (project / tree / "messages.html").unlink()
    assert "Invoice" in rejects(checker, project, "removed")


def test_literal_percentage_prose_is_not_a_format_placeholder(checker, project: Path) -> None:
    def percentage(po):
        po[0].msgid = "Use 10% for ten percent off."
        po[0].msgstr = "Folosiți 10% pentru o reducere de zece procente."

    change_po(project, percentage, recompile=True)
    (project / TREES[0] / "messages.html").unlink()
    (project / TREES[0] / "messages.py").write_text(
        "from django.utils.translation import gettext as _\n"
        "# xgettext:no-python-format\n"
        '_("Use 10% for ten percent off.")\n'
    )
    checker.check_catalogs(project)


@pytest.mark.parametrize(
    "message",
    [
        "One threshold and discount per line, separated by a colon. Use 10000:10% for ten percent from 10000 cents, or 5:500 for 500 cents from five items. The highest qualifying tier applies.",
        "Use threshold:percentage% or threshold:amount on each line.",
    ],
    ids=["percent-for", "percent-or"],
)
def test_literal_percent_production_annotations_survive_real_extraction(
    checker, project: Path, monkeypatch, message: str
) -> None:
    """Exercise the real comment placement, including earlier argument strings."""
    source = (ROOT / "services/platform/apps/promotions/forms.py").read_text()
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == message
    ]
    assert len(calls) == 1
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    statement: ast.AST = calls[0]
    while not isinstance(statement, ast.stmt):
        statement = parents[statement]
    assert statement.end_lineno is not None
    lines = source.splitlines(keepends=True)
    start = statement.lineno - 1
    while start > 0 and lines[start - 1].lstrip().startswith("#"):
        start -= 1
    snippet = textwrap.dedent("".join(lines[start : statement.end_lineno]))
    messages = {
        node.args[0].value
        for node in ast.walk(ast.parse(snippet))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    originals = polib.pofile(str(ROOT / TREES[0] / CATALOG))

    def prepare(po: polib.POFile) -> None:
        po.clear()
        for msgid in sorted(messages):
            original = originals.find(msgid)
            assert original is not None and original.translated()
            po.append(polib.POEntry(msgid=msgid, msgstr=original.msgstr))

    change_po(project, prepare, recompile=True)
    (project / TREES[0] / "messages.html").unlink()
    (project / TREES[0] / "messages.py").write_text(snippet)
    run = subprocess.run

    def inspect_extraction(args, **kwargs):
        result = run(args, **kwargs)
        if "i18n-extract" in args:
            extracted = polib.pofile(str(Path(kwargs["cwd"]) / TREES[0] / CATALOG))
            entry = extracted.find(message)
            assert entry is not None
            assert "no-python-format" in entry.flags, f"Literal percent annotation was not applied: {message!r}"
            assert "python-format" not in entry.flags
            assert "fuzzy" not in entry.flags
        return result

    monkeypatch.setattr(subprocess, "run", inspect_extraction)
    before = files(project)
    checker.check_catalogs(project)
    assert files(project) == before


def test_non_runtime_compiled_metadata_differences_are_accepted(checker, project: Path) -> None:
    path = project / TREES[0] / CATALOG
    po = polib.pofile(str(path))
    po.metadata["Project-Id-Version"] = "different-build"
    po.metadata["PO-Revision-Date"] = "2000-01-01 00:00+0000"
    po.save_as_mofile(str(path.with_suffix(".mo")))
    checker.check_catalogs(project)


@pytest.mark.parametrize(
    "relative", ["Makefile", "services/platform/messages.html", "services/platform/locale/ro/LC_MESSAGES/django.mo"]
)
def test_removing_captured_inputs_during_inspection_is_reported(
    checker, project: Path, monkeypatch, relative: str
) -> None:
    run = subprocess.run

    def remove(args, **kwargs):
        result = run(args, **kwargs)
        if "i18n-extract" in args:
            (project / relative).unlink()
        return result

    monkeypatch.setattr(subprocess, "run", remove)
    with pytest.raises(checker.CatalogCheckError, match="inputs changed") as error:
        checker.check_catalogs(project)
    assert relative in str(error.value)


@pytest.mark.parametrize("header", ["text/plain", "text/plain; charset=ISO-8859-1"])
def test_utf8_header_is_required(checker, project: Path, header: str) -> None:
    change_po(project, lambda po: po.metadata.update({"Content-Type": header}))
    rejects(checker, project, "malformed Romanian header")


@pytest.mark.parametrize(
    "relative", ["services/platform/media", "services/platform/staticfiles", "services/portal/staticfiles"]
)
def test_runtime_directories_are_excluded_before_reading(checker, project: Path, relative: str) -> None:
    directory = project / relative
    directory.mkdir()
    upload = directory / "unreadable.html"
    upload.symlink_to(directory / "missing-target")
    before = files(project)
    checker.check_catalogs(project)
    assert files(project) == before
    assert upload.is_symlink()


def test_shared_python_is_excluded_before_reading(checker, project: Path) -> None:
    source = project / "shared/ui/ignored.py"
    source.symlink_to(project / "missing-target")
    before = files(project)
    checker.check_catalogs(project)
    assert files(project) == before
    assert source.is_symlink()


@pytest.mark.parametrize("relative", ["shared/ui/media", "shared/ui/staticfiles", "services/portal/media"])
def test_runtime_names_elsewhere_are_still_extracted(checker, project: Path, relative: str) -> None:
    # Portal's real development settings use Django's empty MEDIA_ROOT default.
    with (project / "services/portal/config/settings/dev.py").open("a") as handle:
        handle.write("MEDIA_ROOT = ''\n")
    directory = project / relative
    directory.mkdir()
    (directory / "message.html").write_text('{% trans "Still extract this message" %}')
    assert "Still extract this message" in rejects(checker, project, "added")


def test_capture_runtime_roots_match_the_recipe_development_settings(checker) -> None:
    """A changed extraction setting must update capture, rather than silently drift."""
    roots: set[Path] = set()
    for tree in TREES[:2]:
        effective: dict[str, Path] = {}
        for module in ("base", "dev"):
            settings = ast.parse((ROOT / tree / f"config/settings/{module}.py").read_text())
            for node in ast.walk(settings):
                if not isinstance(node, ast.Assign):
                    continue
                names = {target.id for target in node.targets if isinstance(target, ast.Name)}
                selected = names & {"MEDIA_ROOT", "STATIC_ROOT"}
                if not selected:
                    continue
                value = node.value
                assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div), (
                    f"{tree}/{module}: runtime roots changed; update the read-only capture rules"
                )
                assert isinstance(value.left, ast.Name) and value.left.id == "BASE_DIR"
                assert isinstance(value.right, ast.Constant) and isinstance(value.right.value, str)
                for name in selected:
                    effective[name] = Path(tree) / value.right.value
        roots.update(effective.values())
    assert len(roots) == 3
    assert Path("services/portal/staticfiles") in roots
    assert roots == checker._RUNTIME_DIRECTORIES
