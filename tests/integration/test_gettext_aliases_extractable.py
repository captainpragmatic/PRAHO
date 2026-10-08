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


def _aliases(tree: ast.Module) -> list[tuple[int, str, str]]:
    """Every name a gettext function is bound to: `import x as y` and `y = x` / `y = translation.x`."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "django.utils.translation":
            found.extend((node.lineno, alias.name, alias.asname) for alias in node.names if alias.asname)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name | ast.Attribute):
            source = node.value.id if isinstance(node.value, ast.Name) else node.value.attr
            found.extend(
                (node.lineno, source, target.id) for target in node.targets if isinstance(target, ast.Name)
            )
    return [(line, source, name) for line, source, name in found if source in EXTRACTABLE]


def test_gettext_is_only_bound_to_extractable_names() -> None:
    offenders = []
    for base in ("services/platform", "services/portal", "shared"):
        for path in (ROOT / base).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if "tests" in relative.parts or ".venv" in str(relative):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            offenders.extend(
                f"{relative}:{line} {source} as {name}"
                for line, source, name in _aliases(tree)
                if name not in EXTRACTABLE
            )
    assert offenders == []


def test_the_guard_sees_both_alias_forms() -> None:
    tree = ast.parse(
        "from django.utils.translation import gettext as _t\n"
        "from django.utils import translation\n"
        "_l = translation.gettext_lazy\n"
        "_ = gettext\n"
    )
    assert [(source, name) for _line, source, name in _aliases(tree)] == [
        ("gettext", "_t"),
        ("gettext_lazy", "_l"),
        ("gettext", "_"),
    ]
