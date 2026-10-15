"""No template links to "#" (#689).

Buttons and links pointed at "#": a DNS page, analytics, a control panel, plan changes, retries
and support chat that do not exist, so they did nothing. Each now goes to a real page or is gone.
An anchor whose "#" is handled by script carries a data- attribute and is allowed.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

REPO = Path(__file__).resolve().parents[4]
TEMPLATE_ROOTS = (
    REPO / "services/platform/templates",
    REPO / "services/portal/templates",
    REPO / "shared/ui/templates",
)
# A whole tag (an HTML element or a template tag) that links to "#".
_DEAD_LINK = re.compile(r"""<a\b[^>]*\bhref=["']#["'][^>]*>|\{%[^%]*\bhref=["']#["'][^%]*%\}""")


class NoDeadLinksTests(SimpleTestCase):
    def test_no_template_links_to_a_bare_hash(self) -> None:
        offenders = []
        for root in TEMPLATE_ROOTS:
            for path in root.rglob("*.html"):
                if "styleguide" in path.parts:
                    continue
                for match in _DEAD_LINK.finditer(path.read_text(encoding="utf-8")):
                    if " data-" not in match.group(0):
                        line = path.read_text(encoding="utf-8")[: match.start()].count("\n") + 1
                        offenders.append(f"{path.relative_to(REPO)}:{line}")
        self.assertEqual(offenders, [], "links to '#' that lead nowhere")
