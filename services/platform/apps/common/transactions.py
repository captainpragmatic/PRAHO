"""Savepoint isolation for optional database effects."""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from logging import Logger

from django.db import DatabaseError, transaction
from django.db.transaction import TransactionManagementError


@contextmanager
def swallow_application_errors(*, logger: Logger, scope: str, message: str, using: str | None = None) -> Iterator[None]:
    """Swallow application errors only when the caller's transaction remains usable."""
    try:
        yield
    except (DatabaseError, TransactionManagementError):
        raise
    except Exception:
        if transaction.get_connection(using).needs_rollback:
            raise
        logger.exception(f"🔥 [{scope}] {message}")


@contextmanager
def best_effort_atomic(*, logger: Logger, scope: str, message: str, using: str | None = None) -> Iterator[None]:
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
        except Exception:
            transaction.set_rollback(True, using=using)
            # Roll back before logging, including when a service marked needs_rollback.
            stack.close()
            logger.exception(f"🔥 [{scope}] {message}")
