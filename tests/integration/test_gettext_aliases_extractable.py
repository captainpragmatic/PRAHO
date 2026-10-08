"""Every gettext alias must be a name `makemessages` extracts.

xgettext only recognises the standard names. A string marked with another alias (`gettext as _t`)
is never extracted, so the next extraction marks its catalog entry obsolete and it renders in English.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTRACTABLE = {
    "_",
    "gettext",
    "gettext_lazy",
    "gettext_noop",
    "ngettext",
    "ngettext_lazy",
    "pgettext",
    "pgettext_lazy",
    "npgettext",
    "npgettext_lazy",
}


def test_gettext_is_only_imported_under_extractable_names() -> None:
    offenders = []
    for base in ("services/platform/apps", "services/portal/apps", "shared"):
        for path in (ROOT / base).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "django.utils.translation":
                    offenders.extend(
                        f"{path.relative_to(ROOT)}:{node.lineno} {alias.name} as {alias.asname}"
                        for alias in node.names
                        if alias.name in EXTRACTABLE and alias.asname and alias.asname not in EXTRACTABLE
                    )
    assert offenders == []
