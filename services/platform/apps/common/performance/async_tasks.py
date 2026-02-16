"""
Async Task Processing Utilities for PRAHO Platform

Provides enhanced async processing for:
- Long-running provisioning tasks
- Database migrations
- Bulk operations
- Background processing with progress tracking
"""

from __future__ import annotations

import functools
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TaskPriority(Enum):
    """Task priority levels."""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass
class TaskResult:
    """Result of an async task execution."""

    task_id: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    started_at: Any | None = None
    completed_at: Any | None = None
    progress: int = 0
    total_steps: int = 0
    current_step: str = ""

    @property
    def duration_seconds(self) -> float | None:
        """Calculate task duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "total_steps": self.total_steps,
            "current_step": self.current_step,
            "duration_seconds": self.duration_seconds,
        }


class TaskProgressTracker:
    """
    Track progress of long-running tasks.
    Uses cache for real-time progress updates.
    """

    CACHE_PREFIX = "task_progress"
    CACHE_TIMEOUT = 3600  # 1 hour

    def __init__(self, task_id: str, total_steps: int = 100) -> None:
        self.task_id = task_id
        self.total_steps = total_steps
        self._start_time = timezone.now()
        self._cache_key = f"{self.CACHE_PREFIX}:{task_id}"

        # Initialize progress in cache
        self._update_cache(
            {
                "task_id": task_id,
                "status": TaskStatus.RUNNING.value,
                "progress": 0,
                "total_steps": total_steps,
                "current_step": "Initializing...",
                "started_at": self._start_time.isoformat(),
                "completed_at": None,
                "error": None,
            }
        )

    def update(
        self,
        progress: int,
        current_step: str = "",
        status: TaskStatus = TaskStatus.RUNNING,
    ) -> None:
        """Update task progress."""
        data = self._get_cache() or {}
        data.update(
            {
                "progress": min(progress, self.total_steps),
                "current_step": current_step,
                "status": status.value,
            }
        )
        self._update_cache(data)

        logger.debug(f"Task {self.task_id}: {progress}/{self.total_steps} - {current_step}")

    def increment(self, steps: int = 1, current_step: str = "") -> None:
        """Increment progress by steps."""
        data = self._get_cache() or {}
        current_progress = data.get("progress", 0)
        new_progress = min(current_progress + steps, self.total_steps)
        self.update(new_progress, current_step)

    def complete(self, result: Any = None) -> TaskResult:
        """Mark task as completed."""
        completed_at = timezone.now()
        data = self._get_cache() or {}
        data.update(
            {
                "status": TaskStatus.COMPLETED.value,
                "progress": self.total_steps,
                "current_step": "Completed",
                "completed_at": completed_at.isoformat(),
                "result": result,
            }
        )
        self._update_cache(data)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            result=result,
            started_at=self._start_time,
            completed_at=completed_at,
            progress=self.total_steps,
            total_steps=self.total_steps,
        )

    def fail(self, error: str) -> TaskResult:
        """Mark task as failed."""
        completed_at = timezone.now()
        data = self._get_cache() or {}
        data.update(
            {
                "status": TaskStatus.FAILED.value,
                "current_step": f"Failed: {error}",
                "completed_at": completed_at.isoformat(),
                "error": error,
            }
        )
        self._update_cache(data)

        logger.error(f"Task {self.task_id} failed: {error}")

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.FAILED,
            error=error,
            started_at=self._start_time,
            completed_at=completed_at,
            progress=data.get("progress", 0),
            total_steps=self.total_steps,
        )

    def cancel(self) -> TaskResult:
        """Mark task as cancelled."""
        completed_at = timezone.now()
        data = self._get_cache() or {}
        data.update(
            {
                "status": TaskStatus.CANCELLED.value,
                "current_step": "Cancelled",
                "completed_at": completed_at.isoformat(),
            }
        )
        self._update_cache(data)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.CANCELLED,
            started_at=self._start_time,
            completed_at=completed_at,
            progress=data.get("progress", 0),
            total_steps=self.total_steps,
        )

    def get_status(self) -> TaskResult:
        """Get current task status."""
        data = self._get_cache()
        if not data:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.PENDING,
            )

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus(data.get("status", TaskStatus.PENDING.value)),
            result=data.get("result"),
            error=data.get("error"),
            started_at=self._start_time,
            completed_at=timezone.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            progress=data.get("progress", 0),
            total_steps=data.get("total_steps", self.total_steps),
            current_step=data.get("current_step", ""),
        )

    def _get_cache(self) -> dict[str, Any] | None:
        """Get cached progress data."""
        return cache.get(self._cache_key)

    def _update_cache(self, data: dict[str, Any]) -> None:
        """Update cached progress data."""
        cache.set(self._cache_key, data, self.CACHE_TIMEOUT)


def get_task_status(task_id: str) -> TaskResult:
    """Get the status of a task by ID."""
    cache_key = f"{TaskProgressTracker.CACHE_PREFIX}:{task_id}"
    data = cache.get(cache_key)

    if not data:
        return TaskResult(
            task_id=task_id,
            status=TaskStatus.PENDING,
        )

    return TaskResult(
        task_id=task_id,
        status=TaskStatus(data.get("status", TaskStatus.PENDING.value)),
        result=data.get("result"),
        error=data.get("error"),
        started_at=timezone.fromisoformat(data["started_at"]) if data.get("started_at") else None,
        completed_at=timezone.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        progress=data.get("progress", 0),
        total_steps=data.get("total_steps", 100),
        current_step=data.get("current_step", ""),
    )


# Task execution utilities


def generate_task_id(prefix: str = "task") -> str:
    """Generate a unique task ID."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def async_task(
    priority: TaskPriority = TaskPriority.NORMAL,
    timeout: int = 300,
    max_retries: int = 3,
    track_progress: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., str]]:
    """
    Decorator to make a function run as an async task with Django-Q2.

    Usage:
        @async_task(priority=TaskPriority.HIGH, timeout=600)
        def provision_service(service_id: int, tracker: TaskProgressTracker) -> dict:
            tracker.update(10, "Starting provisioning...")
            # ... do work ...
            tracker.update(100, "Completed")
            return {"status": "success"}

        # Execute async - returns task_id
        task_id = provision_service(service_id=123)

        # Check status
        status = get_task_status(task_id)
    """

    def decorator(func: Callable[..., T]) -> Callable[..., str]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> str:
            task_id = generate_task_id(func.__name__)

            # Create progress tracker if enabled
            if track_progress:
                tracker = TaskProgressTracker(task_id)
                kwargs["tracker"] = tracker
            else:
                kwargs["tracker"] = None

            # Queue the task with Django-Q2
            try:
                from django_q.tasks import async_task as q_async_task  # noqa: PLC0415

                q_async_task(
                    _execute_tracked_task,
                    func,
                    task_id,
                    args,
                    kwargs,
                    timeout=timeout,
                    group=f"priority_{priority.value}",
                )

                logger.info(f"Queued async task: {task_id} ({func.__name__})")

            except ImportError:
                # Django-Q not available, run synchronously
                logger.warning("Django-Q not available, running task synchronously")
                _execute_tracked_task(func, task_id, args, kwargs)

            return task_id

        # Add method to run synchronously for testing
        wrapper.sync = func  # type: ignore[attr-defined]

        return wrapper

    return decorator


def _execute_tracked_task(
    func: Callable[..., Any],
    task_id: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    """Execute a task with progress tracking."""
    tracker = kwargs.get("tracker")

    try:
        result = func(*args, **kwargs)

        if tracker:
            tracker.complete(result)

        return result

    except Exception as e:
        logger.exception(f"Task {task_id} failed")

        if tracker:
            tracker.fail(str(e))

        raise


# Bulk operation utilities


class BulkOperationProcessor:
    """
    Process bulk operations efficiently with progress tracking.
    Supports batching, transactions, and error handling.
    """

    def __init__(
        self,
        task_id: str | None = None,
        batch_size: int = 100,
        use_transaction: bool = True,
        continue_on_error: bool = False,
    ) -> None:
        self.task_id = task_id or generate_task_id("bulk")
        self.batch_size = batch_size
        self.use_transaction = use_transaction
        self.continue_on_error = continue_on_error

        self.total_items = 0
        self.processed_items = 0
        self.failed_items = 0
        self.errors: list[dict[str, Any]] = []

        self._tracker: TaskProgressTracker | None = None

    def process(
        self,
        items: list[Any],
        processor_func: Callable[[Any], Any],
    ) -> dict[str, Any]:
        """
        Process a list of items with the given processor function.

        Returns:
            dict with processing statistics and any errors
        """
        self.total_items = len(items)
        self._tracker = TaskProgressTracker(self.task_id, self.total_items)

        results = []
        start_time = time.time()

        # Process in batches
        for i in range(0, len(items), self.batch_size):
            batch = items[i : i + self.batch_size]
            batch_results = self._process_batch(batch, processor_func)
            results.extend(batch_results)

            # Update progress
            self._tracker.update(
                self.processed_items,
                f"Processed {self.processed_items}/{self.total_items} items",
            )

        # Complete tracking
        elapsed = time.time() - start_time
        summary = {
            "task_id": self.task_id,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "failed_items": self.failed_items,
            "success_rate": (
                (self.processed_items - self.failed_items) / self.total_items * 100 if self.total_items > 0 else 0
            ),
            "elapsed_seconds": round(elapsed, 2),
            "items_per_second": round(self.total_items / elapsed, 2) if elapsed > 0 else 0,
            "errors": self.errors[:10],  # Limit errors in response
        }

        if self.failed_items > 0:
            self._tracker.fail(f"{self.failed_items} items failed")
        else:
            self._tracker.complete(summary)

        return summary

    def _process_batch(
        self,
        batch: list[Any],
        processor_func: Callable[[Any], Any],
    ) -> list[Any]:
        """Process a single batch of items."""
        results = []

        if self.use_transaction:
            with transaction.atomic():
                results = self._process_items(batch, processor_func)
        else:
            results = self._process_items(batch, processor_func)

        return results

    def _process_items(
        self,
        items: list[Any],
        processor_func: Callable[[Any], Any],
    ) -> list[Any]:
        """Process individual items."""
        results = []

        for item in items:
            try:
                result = processor_func(item)
                results.append(result)
                self.processed_items += 1

            except Exception as e:
                self.failed_items += 1
                self.processed_items += 1

                error_info = {
                    "item": str(item)[:100],
                    "error": str(e),
                }
                self.errors.append(error_info)

                if not self.continue_on_error:
                    raise

                logger.warning(f"Bulk operation error: {e}")

        return results


# Lock management for distributed task coordination


class DistributedLock:
    """
    Distributed lock using cache backend.
    Prevents concurrent execution of critical tasks.
    """

    LOCK_PREFIX = "lock"

    def __init__(
        self,
        lock_name: str,
        timeout: int = 300,
        blocking: bool = True,
        blocking_timeout: int = 30,
    ) -> None:
        self.lock_name = lock_name
        self.timeout = timeout
        self.blocking = blocking
        self.blocking_timeout = blocking_timeout
        self._cache_key = f"{self.LOCK_PREFIX}:{lock_name}"
        self._lock_id = uuid.uuid4().hex
        self._acquired = False

    def acquire(self) -> bool:
        """Acquire the lock."""
        start_time = time.time()

        while True:
            # Try to acquire
            if self._try_acquire():
                self._acquired = True
                logger.debug(f"Lock acquired: {self.lock_name}")
                return True

            if not self.blocking:
                return False

            # Check timeout
            if time.time() - start_time > self.blocking_timeout:
                logger.warning(f"Lock acquisition timed out: {self.lock_name}")
                return False

            # Wait and retry
            time.sleep(0.1)

    def release(self) -> bool:
        """Release the lock."""
        if not self._acquired:
            return False

        current = cache.get(self._cache_key)
        if current == self._lock_id:
            cache.delete(self._cache_key)
            self._acquired = False
            logger.debug(f"Lock released: {self.lock_name}")
            return True

        return False

    def _try_acquire(self) -> bool:
        """Try to acquire the lock without blocking."""
        # Use cache.add for atomic set-if-not-exists
        return cache.add(self._cache_key, self._lock_id, self.timeout)

    def __enter__(self) -> DistributedLock:
        if not self.acquire():
            raise RuntimeError(f"Failed to acquire lock: {self.lock_name}")
        return self

    def __exit__(self, *args: Any) -> None:
        self.release()

    @property
    def is_locked(self) -> bool:
        """Check if the lock is currently held."""
        return cache.get(self._cache_key) is not None


def with_lock(
    lock_name: str,
    timeout: int = 300,
    blocking: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to execute a function with a distributed lock.

    Usage:
        @with_lock("provision_server_{server_id}")
        def provision_server(server_id: int) -> None:
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            # Format lock name with function arguments
            formatted_name = lock_name.format(**kwargs)

            with DistributedLock(formatted_name, timeout=timeout, blocking=blocking):
                return func(*args, **kwargs)

        return wrapper

    return decorator


# Task scheduling utilities


def schedule_task(
    func: Callable[..., Any],
    schedule_time: Any,
    *args: Any,
    **kwargs: Any,
) -> str:
    """
    Schedule a task to run at a specific time.

    Returns:
        Task ID for tracking
    """
    task_id = generate_task_id(f"scheduled_{func.__name__}")

    try:
        from django_q.tasks import schedule  # noqa: PLC0415

        schedule(
            func,
            *args,
            **kwargs,
            name=task_id,
            schedule_type="O",  # Once
            next_run=schedule_time,
        )

        logger.info(f"Scheduled task {task_id} for {schedule_time}")

    except ImportError:
        logger.warning("Django-Q not available, scheduling not supported")
        return ""

    return task_id


def cancel_scheduled_task(task_id: str) -> bool:
    """Cancel a scheduled task by ID."""
    try:
        from django_q.models import Schedule  # noqa: PLC0415

        deleted, _ = Schedule.objects.filter(name=task_id).delete()
        return deleted > 0

    except ImportError:
        return False
