"""Every customer-actionable platform order error must exist in the portal catalogue.

The platform wraps its preflight messages in gettext, but renders them with str() while
serving an HMAC request, where no customer language is active. They therefore reach the
portal in English. The portal finishes the translation in _localise_platform_error()
(services/portal/apps/orders/views.py) by looking each received string up as a msgid.

That works only while the two sides agree on the exact literal, and nothing at runtime
reports a miss: gettext returns its input unchanged, so a drifted or newly added message
silently reaches a Romanian customer in English. This test is that missing report.

It reads the COMPILED .mo rather than the .po, so an edited catalogue that was never run
through msgfmt fails here instead of in production.
"""

from __future__ import annotations

import ast
import gettext as gettext_module
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFLIGHT = REPO_ROOT / "services" / "platform" / "apps" / "orders" / "preflight.py"
PORTAL_MO = REPO_ROOT / "services" / "portal" / "locale" / "ro" / "LC_MESSAGES" / "django.mo"
PORTAL_DECL = REPO_ROOT / "services" / "portal" / "apps" / "orders" / "platform_messages.py"

_GETTEXT_ALIASES = {"_", "_l", "gettext", "gettext_lazy", "ugettext", "ugettext_lazy"}


def _platform_preflight_literals() -> set[str]:
    """Every string literal the platform passes to gettext in preflight.py."""
    tree = ast.parse(PREFLIGHT.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        if name not in _GETTEXT_ALIASES or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.add(first.value)
    return found


def _portal_declared_messages() -> set[str]:
    """The strings the portal re-declares so extraction cannot obsolete them.

    Parsed rather than imported: this test runs under the platform's settings, and the
    portal module must stay readable from here without importing portal code.
    """
    tree = ast.parse(PORTAL_DECL.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in _GETTEXT_ALIASES or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.add(first.value)
        elif isinstance(first, ast.JoinedStr):
            continue
    return found


def test_the_portal_declaration_matches_the_platform_exactly() -> None:
    """Drift in either direction breaks the translation, so both are failures.

    A message the platform added but the portal never declared is extracted from
    nothing and reaches a customer in English. One the portal still declares after the
    platform dropped it is dead weight that makes the catalogue look complete.
    """
    platform = {s for s in _platform_preflight_literals() if "{" not in s}
    portal = _portal_declared_messages()

    assert not (platform - portal), (
        "the platform emits these but the portal does not declare them, so the next "
        "i18n extraction drops their translations:\n  " + "\n  ".join(repr(s) for s in sorted(platform - portal))
    )
    assert not (portal - platform), (
        "the portal declares these but the platform no longer emits them:\n  "
        + "\n  ".join(repr(s) for s in sorted(portal - platform))
    )


def test_the_extractor_still_finds_the_platform_messages() -> None:
    """Guards the guard: if preflight.py is restructured, the check must not quietly
    start asserting over an empty set and pass forever."""
    literals = _platform_preflight_literals()

    assert len(literals) >= 15, f"expected the preflight message set, found {len(literals)}"
    assert "Please provide your street address" in literals


def test_every_actionable_platform_message_has_a_romanian_translation() -> None:
    """A customer who can act on a message must be able to read it.

    Interpolated messages are excluded deliberately. Their msgid holds the {} template
    while the portal receives the already-formatted string, so a msgid lookup cannot
    match by construction. They report internal catalogue inconsistencies (a product
    went inactive, a price snapshot is missing) that a customer cannot act on anyway,
    and _localise_platform_error passes them through in English rather than dropping them.
    """
    with PORTAL_MO.open("rb") as handle:
        catalogue = gettext_module.GNUTranslations(handle)

    actionable = {s for s in _platform_preflight_literals() if "{" not in s}
    untranslated = sorted(s for s in actionable if catalogue.gettext(s) == s)

    assert not untranslated, (
        "these platform order errors reach a Romanian customer in English; add each to "
        "services/portal/locale/ro/LC_MESSAGES/django.po and run msgfmt:\n  "
        + "\n  ".join(repr(s) for s in untranslated)
    )


PORTAL_VIEWS = REPO_ROOT / "services" / "portal" / "apps" / "orders" / "views.py"


def _portal_profile_keywords() -> tuple[str, ...]:
    """The portal's _PROFILE_KEYWORDS tuple, read from source for the same reason as above."""
    tree = ast.parse(PORTAL_VIEWS.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_PROFILE_KEYWORDS" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, tuple) and value
            return value
    raise AssertionError("services/portal/apps/orders/views.py no longer defines _PROFILE_KEYWORDS")


def _platform_profile_messages() -> set[str]:
    """The messages preflight emits for a missing billing-profile field.

    They are the second element of each pair in preflight's ``required_fields`` table,
    which is what makes them profile errors on the platform side.
    """
    tree = ast.parse(PREFLIGHT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "required_fields" for target in node.targets)
            and isinstance(node.value, ast.List)
        ):
            found = set()
            for pair in node.value.elts:
                assert isinstance(pair, ast.Tuple) and len(pair.elts) == 2
                call = pair.elts[1]
                assert isinstance(call, ast.Call) and isinstance(call.args[0], ast.Constant)
                found.add(call.args[0].value)
            return found
    raise AssertionError("preflight.py no longer defines its required_fields table")


def _classifies_as_profile_error(message: str, keywords: tuple[str, ...]) -> bool:
    # Mirrors _is_profile_error in services/portal/apps/orders/views.py.
    return any(keyword in message.lower() for keyword in keywords)


def test_profile_errors_still_trigger_the_profile_prompt() -> None:
    """The portal shows the profile-completion prompt by keyword-matching the platform's
    English text (#567). A reword such as "Please provide your county/state" to "Region is
    required" would stop the prompt while every other test stayed green, so the
    classification is asserted here in both directions.
    """
    keywords = _portal_profile_keywords()
    profile = _platform_profile_messages()
    others = {s for s in _platform_preflight_literals() if "{" not in s} - profile

    assert len(profile) >= 7, f"expected the billing-profile messages, found {sorted(profile)}"
    missed = sorted(s for s in profile if not _classifies_as_profile_error(s, keywords))
    assert not missed, (
        "these profile errors no longer match _PROFILE_KEYWORDS, so the customer is not "
        "prompted to complete their profile:\n  " + "\n  ".join(repr(s) for s in missed)
    )
    misrouted = sorted(s for s in others if _classifies_as_profile_error(s, keywords))
    assert not misrouted, (
        "these non-profile errors match _PROFILE_KEYWORDS, so the customer sees a generic "
        "profile prompt instead of the reason:\n  " + "\n  ".join(repr(s) for s in misrouted)
    )
