"""Type stubs for django-q models."""

from typing import Any

from django.db import models

class Schedule(models.Model):
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

class OrmQ(models.Model):
    key: str
    payload: bytes
    lock: float | None

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
