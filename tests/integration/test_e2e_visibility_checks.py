"""No e2e check may pass a timeout to `Locator.is_visible()`.

Playwright ignores that argument: `is_visible()` returns at once with what is on the page right now.
`is_visible(timeout=2000)` therefore reads like "wait up to two seconds" while it waits for nothing, and
a check written that way right after an HTMX interaction races the swap. A check that must wait uses a
retrying `expect(locator).to_be_visible()`; a check that only branches on the current state calls
`is_visible()` without a timeout, so it doesn't pretend otherwise.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

E2E = Path(__file__).resolve().parents[1] / "e2e"
# `\s*` also spans newlines, so a call split across lines is caught when whole files are scanned.
_TIMED_IS_VISIBLE = re.compile(r"\.is_visible\(\s*timeout\s*=")


def _timed_is_visible_calls(paths: list[Path], root: Path) -> list[str]:
    """`path:line` of every `is_visible(timeout=…)` call, scanning each file whole."""
    found = []
    for path in paths:
        source = path.read_text()
        for match in _TIMED_IS_VISIBLE.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            found.append(f"{path.relative_to(root)}:{line}")
    return found


class TestE2EVisibilityChecks:
    @pytest.mark.integration
    def test_no_e2e_check_passes_a_timeout_to_is_visible(self) -> None:
        files = sorted(E2E.rglob("*.py"))
        # A broken glob must fail loudly, not check zero files and pass.
        assert len(files) > 20, files
        offenders = _timed_is_visible_calls(files, E2E.parent.parent)
        assert offenders == [], (
            "is_visible() ignores its timeout; use expect(...).to_be_visible() to wait, "
            f"or is_visible() with no timeout to branch: {offenders}"
        )

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("assert badge.is_visible(timeout=5000)\n", ["case.py:1"]),
            ("if row.is_visible( timeout = 2000 ):\n", ["case.py:1"]),
            ("x = 1\nassert badge.is_visible(\n    timeout=5000\n)\n", ["case.py:2"]),
            ("if row.is_visible():\n", []),
            ("expect(badge).to_be_visible(timeout=5000)\n", []),
        ],
    )
    def test_the_scan_flags_only_a_timeout_on_is_visible(self, tmp_path: Path, source: str, expected: list[str]) -> None:
        case = tmp_path / "case.py"
        case.write_text(source)
        assert _timed_is_visible_calls([case], tmp_path) == expected
