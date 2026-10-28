"""No translation may add markup its source string does not have.

Django marks a translated template literal safe, so `{% trans %}`, `{% trans ... as %}` and
`{% blocktranslate %}` print the catalog's text unescaped: thousands of templates rely on the
catalogs holding plain text. Escaping every site is not practical, so the catalogs are checked
instead. A msgstr may not carry more of a markup-relevant character than its msgid does.
"""

from __future__ import annotations

import re
from pathlib import Path

import polib
import pytest

ROOT = Path(__file__).resolve().parents[2]
CATALOGS = sorted(
    path
    for path in ROOT.glob("**/locale/*/LC_MESSAGES/django.po")
    if not any(part.startswith(".venv") or part == "node_modules" for part in path.parts)
)
# Characters that open a tag, close or open an attribute value, or end or escape out of a JS string.
MARKUP = ("<", ">", '"', "'", "`", "\\", "\n", "\r")
TAG = re.compile(r"<[^>]*>")


def _added_markup(msgid: str, msgstr: str) -> list[str]:
    if sorted(TAG.findall(msgid)) != sorted(TAG.findall(msgstr)):
        return ["tags"]  # a message keeps exactly its own tags
    # Outside its tags, a translation may not gain markup characters either: an unclosed
    # "<img ..." borrows its ">" from the template around it.
    source, text = TAG.sub("", msgid), TAG.sub("", msgstr)
    return [char for char in MARKUP if text.count(char) > source.count(char)]


def _offenders(catalog: Path) -> list[str]:
    found = []
    for entry in polib.pofile(str(catalog)):
        if entry.obsolete:
            continue
        pairs = [(entry.msgid, entry.msgstr)]
        pairs += [(entry.msgid_plural if index else entry.msgid, text) for index, text in entry.msgstr_plural.items()]
        for msgid, msgstr in pairs:
            if msgstr and (added := _added_markup(msgid, msgstr)):
                found.append(f"{entry.linenum}: adds {''.join(added)!r}: {msgid[:60]!r} -> {msgstr[:60]!r}")
    return found


def test_the_catalogs_are_found() -> None:
    assert len(CATALOGS) >= 3, CATALOGS  # platform, portal and shared UI, at least Romanian


@pytest.mark.parametrize("catalog", CATALOGS, ids=lambda path: str(path.relative_to(ROOT)))
def test_no_translation_adds_markup(catalog: Path) -> None:
    assert _offenders(catalog) == []


def test_the_check_catches_a_hostile_translation() -> None:
    assert _added_markup("Pricing", "<img src=x onerror=alert(1)>")
    assert _added_markup("Save", "Save' onfocus='x")
    assert not _added_markup('Click "Save"', 'Apăsați "Salvează"')
    assert _added_markup("Save", "Save\n</script>")
    assert not _added_markup("<b>Note</b>: done", "<b>Notă</b>: gata")
    assert _added_markup("<b>Note</b>", "<b onclick=x>Notă</b>")
    assert _added_markup("<b>Note</b>", "<b>Notă</b><img src=x onerror=alert(1) ")


# Sites where a translated value reaches a component or element and is escaped explicitly (2026-10-28
# audit). The catalog check above is the general guard; these keep the explicit escapes in place.
ESCAPED_SITES = {
    "services/platform/templates/orders/order_form.html": ["{% button bt4|force_escape"],
    "services/platform/templates/products/product_detail.html": ["{{ pricing_heading|force_escape }}"],
    "services/portal/templates/billing/proforma_detail.html": [
        '{% alert alert_msg|force_escape variant="danger" title=alert_title|force_escape',
        '{% alert alert_msg|force_escape variant="success" title=alert_title|force_escape',
    ],
    "services/portal/templates/services/service_detail.html": [
        "{% stat_tile st3_label|force_escape st3_age_val|force_escape",
        "{% stat_tile st3_label|force_escape st3_val|force_escape",
        "{{ uptime_text|force_escape }}",
    ],
}


@pytest.mark.parametrize("template", sorted(ESCAPED_SITES))
def test_translated_values_stay_escaped_where_they_reach_markup(template: str) -> None:
    text = (ROOT / template).read_text(encoding="utf-8")
    for site in ESCAPED_SITES[template]:
        assert site in text, f"{template} no longer escapes: {site}"
    if template.endswith("service_detail.html"):
        assert text.count("{{ uptime_text|force_escape }}") == 2  # both uptime tiles
