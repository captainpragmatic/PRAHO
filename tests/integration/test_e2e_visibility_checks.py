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
_TIMED_IS_VISIBLE = re.compile(r"\.is_visible\(\s*timeout\s*=")


class TestE2EVisibilityChecks:
    @pytest.mark.integration
    def test_no_e2e_check_passes_a_timeout_to_is_visible(self) -> None:
        files = sorted(E2E.rglob("*.py"))
        # A broken glob must fail loudly, not check zero files and pass.
        assert len(files) > 20, files
        offenders = [
            f"{path.relative_to(E2E.parent.parent)}:{number}"
            for path in files
            for number, line in enumerate(path.read_text().splitlines(), start=1)
            if _TIMED_IS_VISIBLE.search(line)
        ]
        assert offenders == [], (
            "is_visible() ignores its timeout; use expect(...).to_be_visible() to wait, "
            f"or is_visible() with no timeout to branch: {offenders}"
        )

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("line", "flagged"),
        [
            ("assert badge.is_visible(timeout=5000)", True),
            ("if row.is_visible( timeout = 2000 ):", True),
            ("if row.is_visible():", False),
            ("expect(badge).to_be_visible(timeout=5000)", False),
        ],
    )
    def test_the_pattern_flags_only_a_timeout_on_is_visible(self, line: str, flagged: bool) -> None:
        assert bool(_TIMED_IS_VISIBLE.search(line)) is flagged
