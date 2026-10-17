"""Every download PRAHO serves is private and never cached, and names its file correctly.

A download carries a person's data (an invoice, an export, an attachment), so a shared cache must
never keep it, and a filename outside Latin-1 must survive the header. Each service has one helper,
`apps.common.http.mark_download`, that sets both. This test finds every place production code sets
`Content-Disposition` and requires it to be that helper. The one exception is the Portal's ticket
proxy, which passes the Platform's disposition through unchanged and sets `private, no-store` itself.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SERVICES = (ROOT / "services" / "platform" / "apps", ROOT / "services" / "portal" / "apps")
DIRECT = re.compile(r"""\[\s*["']Content-Disposition["']\s*\]\s*=""")
HELPERS = {Path("services/platform/apps/common/http.py"), Path("services/portal/apps/common/http.py")}
PASSTHROUGH = {Path("services/portal/apps/tickets/views.py")}


def _production_modules() -> list[Path]:
    return [path for base in SERVICES for path in base.rglob("*.py") if "tests" not in path.parts]


@pytest.mark.integration
def test_every_download_response_is_private_no_store() -> None:
    direct = []
    for path in _production_modules():
        relative = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not DIRECT.search(line) or relative in HELPERS:
                continue
            nearby = "\n".join(lines[index : index + 3])
            if relative in PASSTHROUGH and "private, no-store" in nearby:
                continue
            direct.append(f"{relative}:{index + 1}")

    assert direct == [], "set Content-Disposition through mark_download():\n" + "\n".join(direct)


@pytest.mark.integration
def test_both_helpers_mark_the_response_private_and_encode_the_filename() -> None:
    for helper in HELPERS:
        source = (ROOT / helper).read_text(encoding="utf-8")
        assert "content_disposition_header" in source, helper
        assert "private, no-store" in source, helper
