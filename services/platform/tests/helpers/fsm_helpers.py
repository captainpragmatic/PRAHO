"""
FSM test helpers for PRAHO Platform.

Provides force_status() to bypass FSMField(protected=True) for test setup.
The lint_fsm_guardrails.py script ensures __dict__[field] is only used here.

NEVER use force_status() in production code — it exists solely for test setup.
"""

from __future__ import annotations

from django.db import models as django_models


def force_status(
    instance: django_models.Model,
    status: str,
    *,
    field_name: str = "status",
    save: bool = True,
) -> None:
    """Bypass FSM protection for test setup. NEVER use in production code.

    Uses __dict__ assignment to bypass FSMField's __set__ descriptor,
    which would raise AttributeError for protected fields.

    Args:
        instance: Django model instance with an FSMField.
        status: Target status value to set.
        field_name: Name of the status field (default: "status").
        save: Whether to save the instance after setting (default: True).
    """
    instance.__dict__[field_name] = status
    if save:
        instance.save(update_fields=[field_name])
