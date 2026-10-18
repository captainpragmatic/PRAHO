"""
Introspection test: every concrete model in apps.* must either
have an audit signal receiver or be listed in the allowlist.

This ensures no model silently escapes audit coverage when new
models are added. The allowlist must include a justification comment.
"""

from __future__ import annotations

import inspect
import io
import re
import textwrap
import tokenize
from pathlib import Path
from typing import Any

from django.apps import apps
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.test import SimpleTestCase

from apps.audit.signals import audit_user_profile_changes
from apps.users.models import CustomerMembership, User, UserProfile
from tests.audit import _receiver_fixtures

# ── helpers ──────────────────────────────────────────────────────────────────

ALLOWLIST_PATH = Path(__file__).resolve().parents[4] / "scripts" / "audit_model_allowlist.txt"

AUDIT_SIGNALS = (post_save, pre_save, post_delete, pre_delete)

_ALLOWLIST_RE = re.compile(
    r"^(?P<entry>[a-z_]+\.[A-Za-z]+)\s+#\s*(?P<comment>.+)$"
)
_UNCOMMENTED_RE = re.compile(
    r"^(?P<entry>[a-z_]+\.[A-Za-z]+)\s*$"
)


def _parse_allowlist() -> tuple[set[str], set[str]]:
    """Parse the allowlist file.

    Returns (commented_entries, uncommented_entries).
    """
    commented: set[str] = set()
    uncommented: set[str] = set()

    text = ALLOWLIST_PATH.read_text()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ALLOWLIST_RE.match(stripped)
        if m:
            commented.add(m.group("entry"))
            continue
        m = _UNCOMMENTED_RE.match(stripped)
        if m:
            uncommented.add(m.group("entry"))

    return commented, uncommented


def _model_label(model: type) -> str:
    """Return 'app_label.ModelName' for a model class."""
    return f"{model._meta.app_label}.{model.__name__}"


# NAME tokens that prove a receiver actually writes to the audit trail. Checked
# via tokenize (comments cannot fake membership) on the receiver's source.
_AUDIT_API_NAMES = frozenset(
    {
        "AuditService",
        "CustomersAuditService",
        "OrdersAuditService",
        "DomainsAuditService",
        "ProductsAuditService",
        "InfrastructureAuditService",
        "BusinessEventData",
        "AuditEventCreationData",
        "log_security_event",
        "log_simple_event",
        "log_compliance_event",
    }
)


def _name_tokens(function: Any) -> set[str] | None:
    """NAME tokens of one function's own source, or None when the source cannot be read."""
    try:
        source = inspect.getsource(function)
        return {
            tok.string
            for tok in tokenize.generate_tokens(io.StringIO(textwrap.dedent(source)).readline)
            if tok.type == tokenize.NAME
        }
    except (OSError, TypeError, tokenize.TokenizeError, IndentationError):
        return None


def _receiver_audits(receiver: Any, _seen: frozenset[int] = frozenset()) -> bool:
    """True when the receiver, or a helper it calls by name, references the audit API by NAME token.

    A live receiver that merely invalidates a cache must not count as audit
    coverage - the pre-upgrade check accepted ANY receiver, which made the
    coverage guarantee vacuous for models whose only signals never audit.
    Checking the whole defining module was still vacuous: one auditing receiver
    vouched for every other receiver in the same file. So only the receiver's own
    source counts, plus the functions it names that resolve in its module globals
    (receivers routinely delegate to _log_billing_model_event, _handle_status_change),
    followed transitively. tokenize means comments cannot fake membership.
    """
    function = inspect.unwrap(receiver)
    if id(function) in _seen:
        return False
    names = _name_tokens(function)
    if names is None:
        return False
    if names & _AUDIT_API_NAMES:
        return True
    module_globals = getattr(getattr(function, "__func__", function), "__globals__", {})
    seen = _seen | {id(function)}
    for name in names:
        helper = module_globals.get(name)
        if inspect.isfunction(helper) and _receiver_audits(helper, seen):
            return True
    return False


def _has_audit_signal(model: type) -> bool:
    """Check if any signal receiver for this model actually writes audit events."""
    for sig in AUDIT_SIGNALS:
        # The public Signal.has_listeners(sender) only says that SOME receiver exists, which is the
        # check this test replaced because a cache-invalidating receiver passed it. Reading the
        # receivers themselves to see whether they audit has no public API, hence the private call.
        raw_receivers = sig._live_receivers(model)
        receivers = (
            [*raw_receivers[0], *raw_receivers[1]] if isinstance(raw_receivers, tuple) else list(raw_receivers)
        )
        if any(_receiver_audits(r) for r in receivers):
            return True
    return False


def _get_local_concrete_models() -> list[type]:
    """Return all concrete, non-proxy models defined in apps.*."""
    return [
        m
        for m in apps.get_models()
        if m.__module__.startswith("apps.")
        and not m._meta.abstract
        and not m._meta.proxy
    ]


# ── tests ────────────────────────────────────────────────────────────────────

class TestAuditModelCoverage(SimpleTestCase):
    """Every local concrete model must be audit-covered or allow-listed."""

    def test_allowlist_file_exists(self):
        self.assertTrue(
            ALLOWLIST_PATH.exists(),
            f"Allowlist not found at {ALLOWLIST_PATH}",
        )

    def test_all_models_classified(self):
        """Every concrete model must have a signal OR be in the allowlist."""
        commented, uncommented = _parse_allowlist()
        allowlist = commented | uncommented
        models = _get_local_concrete_models()

        unclassified = []
        for model in models:
            label = _model_label(model)
            if label in allowlist:
                continue
            if _has_audit_signal(model):
                continue
            unclassified.append(label)

        unclassified.sort()
        self.assertEqual(
            unclassified,
            [],
            f"\n{len(unclassified)} model(s) have NO audit signal and are NOT in the "
            f"allowlist.\nEither add a post_save/post_delete signal or add them to "
            f"{ALLOWLIST_PATH.name}:\n  " + "\n  ".join(unclassified),
        )

    def test_allowlist_entries_are_real_models(self):
        """Every allowlist entry must correspond to an actual model."""
        commented, uncommented = _parse_allowlist()
        all_entries = commented | uncommented

        known_labels = {_model_label(m) for m in _get_local_concrete_models()}
        stale = sorted(all_entries - known_labels)

        self.assertEqual(
            stale,
            [],
            f"\n{len(stale)} allowlist entry/entries do not match any installed model.\n"
            f"Remove or fix these stale entries in {ALLOWLIST_PATH.name}:\n  "
            + "\n  ".join(stale),
        )

    def test_allowlist_entries_have_comments(self):
        """Every allowlist entry must have a justification comment."""
        _commented, uncommented = _parse_allowlist()

        uncommented_sorted = sorted(uncommented)
        self.assertEqual(
            uncommented_sorted,
            [],
            f"\n{len(uncommented_sorted)} allowlist entry/entries lack a justification "
            f"comment (format: 'app_label.ModelName  # reason'):\n  "
            + "\n  ".join(uncommented_sorted),
        )


class TestAllowlistJustificationsAreTrue(SimpleTestCase):
    """Every "audited via X" claim in the allowlist must name a mechanism that exists.

    The pre-overhaul allowlist carried five entries claiming "audited via parent
    signal" for models whose parents never audited them - a justification nobody
    could falsify because nothing checked it. Any snake_case identifier a comment
    cites (event name, function, module path) must appear somewhere under apps/.
    """

    _IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")

    def test_cited_mechanisms_exist_in_the_codebase(self):
        apps_root = ALLOWLIST_PATH.parents[1] / "services" / "platform" / "apps"
        corpus = "\n".join(
            f.read_text(encoding="utf-8", errors="ignore") for f in apps_root.rglob("*.py")
        )

        unbacked: list[str] = []
        for line in ALLOWLIST_PATH.read_text().splitlines():
            m = _ALLOWLIST_RE.match(line.strip())
            if not m or "audited via" not in m.group("comment"):
                continue
            claim = m.group("comment").split("audited via", 1)[1]
            identifiers = self._IDENTIFIER_RE.findall(claim)
            if identifiers and not any(name in corpus for name in identifiers):
                unbacked.append(f"{m.group('entry')}: none of {identifiers} found under apps/")

        self.assertEqual(
            unbacked,
            [],
            "Allowlist justification cites a mechanism that does not exist:\n" + "\n".join(unbacked),
        )


class TestReceiverAuditsInspectsTheReceiver(SimpleTestCase):
    """The detector must be able to fail: one auditing receiver must not vouch for its neighbours."""

    def test_a_receiver_that_audits_directly_counts(self):
        self.assertTrue(_receiver_audits(_receiver_fixtures.audits_directly))

    def test_a_receiver_that_delegates_to_an_auditing_helper_counts(self):
        self.assertTrue(_receiver_audits(_receiver_fixtures.audits_through_a_helper))

    def test_a_non_auditing_receiver_does_not_count_because_its_module_audits(self):
        self.assertFalse(_receiver_audits(_receiver_fixtures.only_invalidates_a_cache))

    def test_a_self_calling_receiver_terminates_and_does_not_count(self):
        self.assertFalse(_receiver_audits(_receiver_fixtures.loops_through_itself))


def _audit_signals_receivers(signal: Any, model: type) -> list[Any]:
    """Receivers of `signal` for `model` that are defined in apps.audit.signals and write audit events."""
    raw_receivers = signal._live_receivers(model)
    receivers = [*raw_receivers[0], *raw_receivers[1]] if isinstance(raw_receivers, tuple) else list(raw_receivers)
    return [
        r
        for r in receivers
        if getattr(inspect.unwrap(r), "__module__", "") == "apps.audit.signals" and _receiver_audits(r)
    ]


class TestIdentityModelsAreAuditedByTheAuditSignals(SimpleTestCase):
    """User, UserProfile and CustomerMembership are audited by apps.audit.signals itself.

    The model-coverage test above accepts a receiver from any module, so it keeps passing if the
    audit receivers for these models are removed while some other app happens to audit them too.
    """

    def test_each_identity_model_has_an_auditing_receiver_in_the_audit_signals_module(self):
        for model in (User, UserProfile, CustomerMembership):
            with self.subTest(model=model.__name__):
                self.assertTrue(_audit_signals_receivers(post_save, model))

    def test_a_membership_deletion_is_audited_by_the_audit_signals_module(self):
        self.assertTrue(_audit_signals_receivers(pre_delete, CustomerMembership))

    def test_the_check_fails_when_the_receiver_is_disconnected(self):
        post_save.disconnect(audit_user_profile_changes, sender=User)
        try:
            self.assertEqual(_audit_signals_receivers(post_save, User), [])
        finally:
            post_save.connect(audit_user_profile_changes, sender=User)
        self.assertTrue(_audit_signals_receivers(post_save, User))
