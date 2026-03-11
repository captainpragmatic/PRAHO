from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import connections
from django.utils import timezone

DEFAULT_PARTITION_MONTHS_AHEAD = 3
DEFAULT_ARCHIVE_ROOT = "var/partition-archives"


@dataclass(frozen=True)
class EventPartitionPolicy:
    slug: str
    table_name: str
    partition_column: str
    keep_attached_months: int
    create_ahead_months: int
    archive_retention_days: int | None = None
    archive_required: bool = True

    @property
    def archive_root(self) -> Path:
        configured = getattr(settings, "EVENT_PARTITION_ARCHIVE_ROOT", DEFAULT_ARCHIVE_ROOT)
        return Path(configured) / self.table_name


EVENT_PARTITION_POLICIES: tuple[EventPartitionPolicy, ...] = (
    EventPartitionPolicy(
        slug="audit_events",
        table_name="audit_events",
        partition_column="timestamp",
        keep_attached_months=3,
        create_ahead_months=DEFAULT_PARTITION_MONTHS_AHEAD,
        archive_retention_days=2555,
    ),
    EventPartitionPolicy(
        slug="integration_webhook_events",
        table_name="integration_webhook_events",
        partition_column="received_at",
        keep_attached_months=3,
        create_ahead_months=DEFAULT_PARTITION_MONTHS_AHEAD,
        archive_retention_days=365,
    ),
    EventPartitionPolicy(
        slug="billing_usage_events",
        table_name="billing_usage_events",
        partition_column="timestamp",
        keep_attached_months=13,
        create_ahead_months=DEFAULT_PARTITION_MONTHS_AHEAD,
        archive_retention_days=730,
    ),
)


def month_floor(value: date) -> date:
    return value.replace(day=1)


def add_months(value: date, months: int) -> date:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    return date(year, month, 1)


def get_event_partition_policies() -> tuple[EventPartitionPolicy, ...]:
    return EVENT_PARTITION_POLICIES


class EventPartitionService:
    def __init__(self, using: str = "default") -> None:
        self.connection = connections[using]

    def get_status(self) -> dict[str, dict[str, Any]]:
        status: dict[str, dict[str, Any]] = {}
        for policy in get_event_partition_policies():
            status[policy.slug] = self._get_policy_status(policy)
        return status

    def plan_operations(self, reference_time: datetime | None = None) -> dict[str, dict[str, Any]]:
        now = reference_time or timezone.now()
        plan: dict[str, dict[str, Any]] = {}
        for policy in get_event_partition_policies():
            current_month = month_floor(now.date())
            future_months = [
                self._partition_name(policy, add_months(current_month, offset))
                for offset in range(policy.create_ahead_months + 1)
            ]
            cutoff_month = add_months(current_month, -policy.keep_attached_months)
            plan[policy.slug] = {
                "table_name": policy.table_name,
                "create_partitions": future_months,
                "detach_before": cutoff_month.isoformat(),
                "archive_root": str(policy.archive_root),
                "archive_retention_days": policy.archive_retention_days,
            }
        return plan

    def ensure_future_partitions(self, reference_time: datetime | None = None, dry_run: bool = False) -> list[str]:
        if self.connection.vendor != "postgresql":
            return []

        now = reference_time or timezone.now()
        statements: list[str] = []
        with self.connection.cursor() as cursor:
            for policy in get_event_partition_policies():
                if not self._is_partitioned(policy.table_name, cursor):
                    continue

                current_month = month_floor(now.date())
                for offset in range(policy.create_ahead_months + 1):
                    month_start = add_months(current_month, offset)
                    month_end = add_months(month_start, 1)
                    partition_name = self._partition_name(policy, month_start)
                    sql = (
                        f"CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF {policy.table_name} "
                        f"FOR VALUES FROM ('{month_start.isoformat()}') TO ('{month_end.isoformat()}');"
                    )
                    statements.append(sql)
                    if not dry_run:
                        cursor.execute(sql)
        return statements

    def _get_policy_status(self, policy: EventPartitionPolicy) -> dict[str, Any]:
        if self.connection.vendor != "postgresql":
            return {
                "table_name": policy.table_name,
                "status": "unsupported_backend",
                "keep_attached_months": policy.keep_attached_months,
                "archive_retention_days": policy.archive_retention_days,
            }

        with self.connection.cursor() as cursor:
            exists = self._table_exists(policy.table_name, cursor)
            if not exists:
                return {
                    "table_name": policy.table_name,
                    "status": "missing",
                    "keep_attached_months": policy.keep_attached_months,
                    "archive_retention_days": policy.archive_retention_days,
                }

            partitioned = self._is_partitioned(policy.table_name, cursor)
            partitions = self._list_partitions(policy.table_name, cursor) if partitioned else []

        return {
            "table_name": policy.table_name,
            "status": "partitioned" if partitioned else "not_partitioned",
            "keep_attached_months": policy.keep_attached_months,
            "archive_retention_days": policy.archive_retention_days,
            "attached_partitions": partitions,
            "archive_root": str(policy.archive_root),
        }

    def _table_exists(self, table_name: str, cursor: Any) -> bool:
        cursor.execute("SELECT to_regclass(%s)", [table_name])
        result = cursor.fetchone()
        return bool(result and result[0])

    def _is_partitioned(self, table_name: str, cursor: Any) -> bool:
        cursor.execute(
            """
            SELECT EXISTS(
                SELECT 1
                FROM pg_partitioned_table p
                JOIN pg_class c ON c.oid = p.partrelid
                WHERE c.relname = %s
            )
            """,
            [table_name],
        )
        result = cursor.fetchone()
        return bool(result and result[0])

    def _list_partitions(self, table_name: str, cursor: Any) -> list[str]:
        cursor.execute(
            """
            SELECT child.relname
            FROM pg_inherits
            JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
            JOIN pg_class child ON child.oid = pg_inherits.inhrelid
            WHERE parent.relname = %s
            ORDER BY child.relname
            """,
            [table_name],
        )
        return [row[0] for row in cursor.fetchall()]

    def _partition_name(self, policy: EventPartitionPolicy, month_start: date) -> str:
        return f"{policy.table_name}_{month_start.year}_{month_start.month:02d}"
