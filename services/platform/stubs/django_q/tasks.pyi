"""Type stubs for django-q tasks."""

from collections.abc import Callable
from datetime import datetime
from typing import Any

def async_task(
    func: str | Callable[..., Any], *args: Any, hook: str | None = None, group: str | None = None, **kwargs: Any
) -> str: ...
def schedule(
    func: str | Callable[..., Any],
    *args: Any,
    name: str | None = None,
    hook: str | None = None,
    schedule_type: str = "O",
    minutes: int | None = None,
    repeats: int = -1,
    next_run: datetime | None = None,
    **kwargs: Any,
) -> Any: ...
def result(task_id: str, wait: int = 0) -> Any: ...
def fetch(task_id: str, wait: int = 0) -> Any: ...
def count_group(group: str) -> int: ...
