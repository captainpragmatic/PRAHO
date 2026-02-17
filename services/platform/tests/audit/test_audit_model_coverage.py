"""
Introspection test: every concrete model in apps.* must either
have an audit signal receiver or be listed in the allowlist.

This ensures no model silently escapes audit coverage when new
models are added. The allowlist must include a justification comment.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.apps import apps
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.test import SimpleTestCase

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


def _has_audit_signal(model: type) -> bool:
    """Check if *any* audit signal type has a live receiver for this model."""
    for sig in AUDIT_SIGNALS:
        raw_receivers = sig._live_receivers(model)
        if isinstance(raw_receivers, tuple):
            sync_receivers, async_receivers = raw_receivers
            if sync_receivers or async_receivers:
                return True
        elif raw_receivers:
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
