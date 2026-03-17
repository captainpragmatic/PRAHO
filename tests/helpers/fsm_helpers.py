"""
FSM test helpers — project-root re-export for E2E ORM tests.

Canonical source: services/platform/tests/helpers/fsm_helpers.py
This file exists because project-root tests/ shadows platform tests/ on PYTHONPATH.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models as django_models


def force_status(
    instance: django_models.Model,
    status: str,
    *,
    field_name: str = "status",
    save: bool = True,
) -> None:
    """Bypass FSM protection for test setup. NEVER use in production code."""
    if not getattr(settings, "TESTING", False):
        raise RuntimeError(
            "force_status() is a test-only helper and must not be called in production. "
            "Set settings.TESTING = True in your test settings to enable it."
        )
    instance.__dict__[field_name] = status
    if save:
        instance.save(update_fields=[field_name])
