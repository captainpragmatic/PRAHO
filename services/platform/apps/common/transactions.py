"""Savepoint isolation for optional database effects."""

import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ContextDecorator, ExitStack, contextmanager
from logging import Logger
from types import TracebackType
from typing import Self

from django.db import DatabaseError, InterfaceError, transaction
from django.db.transaction import TransactionManagementError


class _SuppressingContextDecorator(ContextDecorator, AbstractContextManager[None, bool]):
    """Expose exception suppression while preserving generator and decorator semantics."""

    def __init__(self, factory: Callable[[], AbstractContextManager[None, bool | None]]) -> None:
        self._factory = factory
        self._context = factory()

    def __enter__(self) -> None:
        return self._context.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        return bool(self._context.__exit__(exc_type, exc_value, traceback))

    def _recreate_cm(self) -> Self:
        return type(self)(self._factory)


def swallow_application_errors(
    *, logger: Logger, scope: str, message: str, using: str | None = None
) -> _SuppressingContextDecorator:
    """Swallow application errors only when the caller's transaction remains usable."""
    return _SuppressingContextDecorator(
        lambda: _swallow_application_errors(logger=logger, scope=scope, message=message, using=using)
    )


@contextmanager
def _swallow_application_errors(
    *, logger: Logger, scope: str, message: str, using: str | None = None
) -> Iterator[None]:
    """Swallow application errors only when the caller's transaction remains usable."""
    try:
        yield
    except (DatabaseError, InterfaceError, TransactionManagementError):
        raise
    except Exception:
        if transaction.get_connection(using).needs_rollback:
            raise
        logger.exception(f"🔥 [{scope}] {message}")


def best_effort_atomic(
    *, logger: Logger, scope: str, message: str, using: str | None = None, level: int = logging.ERROR
) -> _SuppressingContextDecorator:
    """Roll back body failures without hiding an unusable transaction or failed entry.

    ``level`` sets how the swallowed failure is logged (always with its traceback); use
    logging.CRITICAL where a failure needs manual review.
    """
    return _SuppressingContextDecorator(
        lambda: _best_effort_atomic(logger=logger, scope=scope, message=message, using=using, level=level)
    )


@contextmanager
def _best_effort_atomic(
    *, logger: Logger, scope: str, message: str, using: str | None = None, level: int = logging.ERROR
) -> Iterator[None]:
    """Roll back body failures without hiding an unusable transaction or failed entry."""
    connection = transaction.get_connection(using)
    if connection.needs_rollback:
        raise TransactionManagementError(
            "Cannot run a best-effort effect inside a transaction that needs rollback."
        ) from connection.rollback_exc

    with ExitStack() as stack:
        # Entry is deliberately outside the body catch: a failed SAVEPOINT must propagate.
        stack.enter_context(transaction.atomic(using=using))
        try:
            yield
        except InterfaceError:
            raise
        except Exception:
            transaction.set_rollback(True, using=using)
            # Roll back before logging, including when a service marked needs_rollback.
            stack.close()
            if connection.needs_rollback or connection.closed_in_transaction:
                raise
            if level == logging.ERROR:
                logger.exception(f"🔥 [{scope}] {message}")
            else:
                logger.log(level, f"🔥 [{scope}] {message}", exc_info=True)

    if connection.needs_rollback or connection.closed_in_transaction:
        raise TransactionManagementError(
            "Best-effort effect could not restore a usable transaction."
        ) from connection.rollback_exc
