"""
Django-Q2 queue utilities for PRAHO Platform
Type-safe task queueing with proper mypy support.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from django_q.tasks import async_task


def queue(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> str:
    """Enqueue a callable via django-q2; returns task id."""
    # Django-Q2 async_task signature: async_task(func, *args, **kwargs)
    return async_task(func, *args, **kwargs)


def queue_by_name(func_path: str, *args: Any, **kwargs: Any) -> str:
    """Enqueue a task by dotted path (prevents import cycles in signals)."""
    return async_task(func_path, *args, **kwargs)
