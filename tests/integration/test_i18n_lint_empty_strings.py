"""The i18n coverage lint treats an empty string as technical, never as untranslated text."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_lint_module() -> ModuleType:
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "lint_i18n_coverage.py"
    spec = importlib.util.spec_from_file_location("lint_i18n_coverage", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _codes(tmp_path: Path, source: str) -> list[str]:
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")
    issues, error = _load_lint_module().scan_python_file(target)
    assert error is None
    return [issue.code for issue in issues]


@pytest.mark.parametrize(
    "source",
    [
        'Address.objects.update(label="")\n',
        'Field(help_text="", verbose_name="")\n',
        'raise ValidationError("")\n',
        'messages.error(request, "")\n',
        'short_description = ""\n',
        'CHOICES = (("none", ""),)\n',
    ],
)
def test_an_empty_string_is_not_flagged(tmp_path: Path, source: str) -> None:
    assert _codes(tmp_path, source) == []


def test_untranslated_text_is_still_flagged(tmp_path: Path) -> None:
    assert _codes(tmp_path, 'Field(label="Home address")\n') == ["I18N006"]
