"""Savepoint isolation for optional database effects, and the no-transaction guard (ADR-0045)."""

import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ContextDecorator, ExitStack, contextmanager
from logging import Logger
from types import TracebackType
from typing import Self

from django.db import DatabaseError, InterfaceError, transaction
from django.db.transaction import TransactionManagementError


def is_outside_transaction(using: str | None = None) -> bool:
    """True when a write commits immediately: no atomic block and autocommit on.

    Provider mutations are only sound when each phase commits on its own (ADR-0045): inside an
    enclosing atomic block a claim is only a savepoint, so an outer rollback erases the record of
    a call the provider already saw. Django also lets a caller turn autocommit off with
    ``set_autocommit(False)`` without opening an atomic block, so checking ``in_atomic_block``
    alone lets that case through.
    """
    connection = transaction.get_connection(using)
    return connection.get_autocommit() and not connection.in_atomic_block


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


def _record_if_audit_failure(error: BaseException) -> None:
    """Count a swallowed audit write (deferred import: the counter store is a model)."""
    from apps.common import audit_failures  # noqa: PLC0415  # Deferred: models are not ready when this module loads

    audit_failures.record(error)


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
    except Exception as error:
        if transaction.get_connection(using).needs_rollback:
            raise
        _record_if_audit_failure(error)
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
        except Exception as error:
            transaction.set_rollback(True, using=using)
            # Roll back before logging, including when a service marked needs_rollback.
            stack.close()
            if connection.needs_rollback or connection.closed_in_transaction:
                raise
            # A swallowed audit write is a missed event: count it, now the savepoint is gone.
            _record_if_audit_failure(error)
            if level == logging.ERROR:
                logger.exception(f"🔥 [{scope}] {message}")
            else:
                logger.log(level, f"🔥 [{scope}] {message}", exc_info=True)

    if connection.needs_rollback or connection.closed_in_transaction:
        raise TransactionManagementError(
            "Best-effort effect could not restore a usable transaction."
        ) from connection.rollback_exc
