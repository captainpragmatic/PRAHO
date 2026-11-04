"""Short-lived safety observations, isolated from the authentication transaction."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from time import monotonic

from django.conf import settings
from django.db import DatabaseError, InterfaceError, connection, transaction
from django.utils import timezone

from .addresses import pack_address
from .models import CustomerIPObservation

logger = logging.getLogger(__name__)
LOCK_TIMEOUT = "1000ms"
STATEMENT_TIMEOUT = "1500ms"
SQLITE_BUSY_MILLISECONDS = 1000
RECORDING_SECONDS = 2.0
RECORDING_BATCH = 100


@dataclass(frozen=True)
class ObservationResult:
    healthy: bool
    reason: str
    customer_count: int = 0


class _ObservationTimeoutError(Exception):
    """An optional observation must not consume the successful login's call budget."""


@contextmanager
def _sqlite_timeout() -> Iterator[None]:
    original = None
    if connection.vendor == "sqlite":
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA busy_timeout")
            original = cursor.fetchone()[0]
            # SQLite PRAGMA assignment cannot bind parameters; this value is a fixed integer constant.
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query
            cursor.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_MILLISECONDS}")
    try:
        yield
    finally:
        if original is not None:
            try:
                with connection.cursor() as cursor:
                    # Restore only the integer read from this connection; int() excludes SQL syntax.
                    # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query
                    cursor.execute(f"PRAGMA busy_timeout = {int(original)}")
            except (DatabaseError, InterfaceError):
                logger.warning("Customer IP observation timeout state could not be restored")


def _write_observations(user_id: int, customer_ids: list[int], family: int, packed: bytes, deadline: float) -> None:
    now = timezone.now()
    for offset in range(0, len(customer_ids), RECORDING_BATCH):
        if monotonic() >= deadline:
            raise _ObservationTimeoutError
        rows = [
            CustomerIPObservation(
                user_id=user_id, customer_id=customer_id, address_family=family, address=packed, last_seen_at=now
            )
            for customer_id in customer_ids[offset : offset + RECORDING_BATCH]
        ]
        CustomerIPObservation.objects.bulk_create(
            rows,
            update_conflicts=True,
            update_fields=("last_seen_at", "updated_at"),
            unique_fields=("user", "customer", "address_family", "address"),
            batch_size=RECORDING_BATCH,
        )
    if monotonic() >= deadline:
        raise _ObservationTimeoutError


def record_recent_customer_ip(*, user_id: int, ip: str | None) -> ObservationResult:
    """Own the entire COMMIT and fresh user lock, so an erasure cannot be repopulated.

    The caller has already committed password/MFA authentication and its session.
    Deferred foreign-key failures belong solely to this optional transaction.
    """
    if not getattr(settings, "CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED", False):
        return ObservationResult(True, "disabled")
    if not ip:
        return ObservationResult(False, "no_trusted_ip")
    try:
        family, packed = pack_address(ip)
    except (ValueError, TypeError):
        return ObservationResult(False, "no_trusted_ip")
    from apps.users.models import CustomerMembership, User  # noqa: PLC0415 -- cross-app runtime boundary

    deadline = monotonic() + RECORDING_SECONDS
    try:
        with _sqlite_timeout(), transaction.atomic(durable=True):
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('lock_timeout', %s, true)", [LOCK_TIMEOUT])
                    cursor.execute("SELECT set_config('statement_timeout', %s, true)", [STATEMENT_TIMEOUT])
            user = User.objects.select_for_update(no_key=True).filter(pk=user_id).first()
            if user is None or not user.is_active:
                return ObservationResult(True, "inactive")
            customer_ids = list(
                CustomerMembership.objects.filter(user_id=user_id, is_active=True)
                .order_by("customer_id")
                .values_list("customer_id", flat=True)
            )
            _write_observations(user_id, customer_ids, family, packed, deadline)
        return ObservationResult(True, "recorded", len(customer_ids))
    except (DatabaseError, InterfaceError, RuntimeError, _ObservationTimeoutError) as error:
        logger.warning("Customer IP observation recording unavailable (%s)", type(error).__name__)
        return ObservationResult(False, "unavailable")
