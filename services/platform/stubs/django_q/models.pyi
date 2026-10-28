"""Type stubs for django-q models."""

from typing import Any, ClassVar, TypedDict

from django.db import models

class Schedule(models.Model):
    ONCE: ClassVar[str]
    MINUTES: ClassVar[str]
    HOURLY: ClassVar[str]
    DAILY: ClassVar[str]
    WEEKLY: ClassVar[str]
    MONTHLY: ClassVar[str]
    QUARTERLY: ClassVar[str]
    YEARLY: ClassVar[str]
    CRON: ClassVar[str]
    name: str
    func: str
    schedule_type: str
    minutes: int | None
    repeats: int
    next_run: Any
    task: str | None
    hook: str | None
    kwargs: dict[str, Any]

    def __init__(self, **kwargs: Any) -> None: ...
    def save(self, *args: Any, **kwargs: Any) -> None: ...

class _OrmTask(TypedDict, total=False):
    func: str
    args: tuple[object, ...]
    kwargs: dict[str, object]

class OrmQ(models.Model):
    key: str
    payload: bytes
    lock: float | None
    task: _OrmTask

    def __init__(self, **kwargs: Any) -> None: ...
    def save(self, *args: Any, **kwargs: Any) -> None: ...

class Task(models.Model):
    id: str
    name: str
    func: str
    started: Any
    stopped: Any
    result: Any
    success: bool

    def __init__(self, **kwargs: Any) -> None: ...
    def save(self, *args: Any, **kwargs: Any) -> None: ...
