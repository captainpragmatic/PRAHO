"""The portal's copy of the PORTAL_ID pattern is the platform's (#751 follow-up).

The portal cannot import platform code, so it keeps its own copy of the pattern the platform's registry
uses for portal ids. A copy that drifted would let a portal start with an id the platform never matches.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERN = re.compile(r'^PORTAL_ID_RE = re\.compile\(r"(?P<pattern>[^"]+)"\)', re.M)


def _pattern(relative: str) -> str:
    match = PATTERN.search((ROOT / relative).read_text())
    assert match, f"no PORTAL_ID_RE in {relative}"
    return match["pattern"]


def test_the_portal_and_the_platform_spell_portal_ids_alike() -> None:
    platform = _pattern("services/platform/apps/common/portal_hmac.py")
    portal = _pattern("services/portal/apps/common/signing.py")

    assert portal == platform
