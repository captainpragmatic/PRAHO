"""No template or platform script states Romania's standard VAT rate as a literal (#689).

Romania's rate changed from 19% to 21% in August 2025, and a customer's rate is not always the
supplier's: reverse charge and non-EU customers pay 0%, and a tax profile may carry a custom rate.
A literal "21%", 0.21 or 1.21 in a page is therefore wrong for someone today and for everyone at
the next change. Rates reach pages from TaxService through the view, never from the markup.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[4]
SCANNED_ROOTS = (
    ROOT / "services" / "platform" / "templates",
    ROOT / "services" / "portal" / "templates",
    ROOT / "shared" / "ui" / "templates",
    ROOT / "services" / "platform" / "static" / "js",
)
SCANNED_SUFFIXES = {".html", ".txt", ".js"}

# "21%" / "21 %" / "21.00%", "0.21" / "0.2100" and "1.21" as whole numbers. The look-behinds keep
# out other numbers that end in the digits (121%, 3.21) and template names such as `bt21 %}`.
VAT_LITERAL = re.compile(
    r"(?<![\w.,])21(?:[.,]0+)?\s?%(?![}\w])"
    r"|(?<![\w.,])0[.,]210*(?![\d])"
    r"|(?<![\w.,])1[.,]210*(?![\d])"
)

# Path (relative to ROOT) -> line substrings that are genuine non-VAT matches. Keep it empty
# unless a match is provably not a VAT rate, and say why next to the entry.
ALLOWLIST: dict[str, tuple[str, ...]] = {}


def _is_vendored(path: Path) -> bool:
    return "vendor" in path.parts or path.name.endswith(".min.js")


class NoHardcodedVatRatesTests(SimpleTestCase):
    def test_the_pattern_finds_vat_literals_and_ignores_lookalikes(self) -> None:
        for text in ("21% (Standard)", "TVA 21 %", "rate = 0.21;", "0.2100", "x * 1.21", "21.00%"):
            self.assertRegex(text, VAT_LITERAL)
        for text in ('{% trans "Cancel" as bt21 %}', "121%", "3.21", "0.215", "2021", "10.21"):
            self.assertNotRegex(text, VAT_LITERAL)

    def test_no_template_or_script_hard_codes_the_vat_rate(self) -> None:
        scanned = 0
        offenders: list[str] = []
        for root in SCANNED_ROOTS:
            self.assertTrue(root.is_dir(), f"scanned root is missing: {root}")
            for path in sorted(root.rglob("*")):
                if path.suffix not in SCANNED_SUFFIXES or not path.is_file() or _is_vendored(path):
                    continue
                scanned += 1
                relative = path.relative_to(ROOT).as_posix()
                allowed = ALLOWLIST.get(relative, ())
                for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                    if VAT_LITERAL.search(line) and not any(token in line for token in allowed):
                        offenders.append(f"{relative}:{number}: {line.strip()}")

        self.assertGreater(scanned, 100, "the scan found too few files to mean anything")
        self.assertEqual(offenders, [], "VAT rates must come from TaxService, not literals")
