"""Owner-scoped publication of measured usage, with no billing or provider writes."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4, uuid5
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .service_models import Service
from .virtualmin_migration_models import account_blocks_reconcile
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_usage_models import AccountUsageState, NodeUsageSyncState, UsageInterval, UsageReading

logger = logging.getLogger(__name__)
STALE_AFTER = timedelta(hours=6)
MIB = 1024**2
MAX_VALUE = (1 << 63) - 1
MAX_DOMAIN_ID = 30
MAX_RECORDS = 2000
MAX_PROJECTION = (1 << 31) - 1


def enabled() -> bool:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return bool(SettingsService.get_setting("provisioning.usage_sync_enabled", True))


def observations_apply(service: Service) -> bool:
    """Other providers retain their own usage source when this feature is enabled."""
    return VirtualminAccount.objects.filter(service=service).exists() and (
        enabled() or AccountUsageState.objects.filter(account__service=service).exists()
    )


def month(as_of: datetime) -> tuple[datetime, datetime]:
    local = as_of.astimezone(ZoneInfo(settings.TIME_ZONE))
    start = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start + timedelta(days=32)).replace(day=1)
    return start.astimezone(UTC), end.astimezone(UTC)


def timestamp(value: object) -> datetime:
    parsed = parse_datetime(value) if isinstance(value, str) else None
    if parsed is None or timezone.is_naive(parsed) or parsed > timezone.now() + timedelta(seconds=5):
        raise ValueError("Invalid usage timestamp")
    return parsed


def integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_VALUE:
        raise ValueError("Invalid usage quantity")
    return value


@transaction.atomic
def current_state(account: VirtualminAccount) -> AccountUsageState:
    account = (
        VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
        .select_related("service")
        .get(pk=account.pk)
    )
    state, _ = AccountUsageState.objects.get_or_create(
        account=account,
        defaults={
            "service_id_snapshot": account.service_id,
            "customer_id_snapshot": account.service.customer_id,
            "server_id_snapshot": account.server_id,
            "chain_epoch_snapshot": account.chain_epoch,
            "gauge_not_before": account.created_at,
        },
    )
    if (state.service_id_snapshot, state.customer_id_snapshot) != (account.service_id, account.service.customer_id):
        reset_owner_scope(account.pk)
        state.refresh_from_db()
    if state.server_id_snapshot != account.server_id:
        move_interval(account.pk, account.server_id)
        state.refresh_from_db()
    if state.chain_epoch_snapshot != account.chain_epoch:
        state.chain_epoch_snapshot = account.chain_epoch
        state.gauge_not_before = timezone.now()
        state.disk_reading = None
        state.save(update_fields=["chain_epoch_snapshot", "gauge_not_before", "disk_reading", "updated_at"])
    UsageInterval.objects.get_or_create(
        account=account,
        ended_at__isnull=True,
        defaults={
            "owner_scope": state.owner_scope,
            "server_id": account.server_id,
            "server_id_snapshot": account.server_id,
            "started_at": state.owner_started_at,
        },
    )
    return state


def reset_owner_scope(account_id: UUID) -> None:
    """Caller holds the account lock; every ownership write, including bulk, calls here."""
    now = timezone.now()
    account = VirtualminAccount.objects.select_related("service").get(pk=account_id)
    previous, _ = AccountUsageState.objects.get_or_create(
        account_id=account_id,
        defaults={
            "service_id_snapshot": account.service_id,
            "customer_id_snapshot": account.service.customer_id,
            "server_id_snapshot": account.server_id,
            "chain_epoch_snapshot": account.chain_epoch,
        },
    )
    UsageInterval.objects.filter(account_id=account_id, ended_at__isnull=True).update(ended_at=now)
    AccountUsageState.objects.filter(account_id=account_id).update(
        owner_scope=uuid4(),
        owner_started_at=now,
        owner_start_known=True,
        gauge_not_before=now,
        disk_reading=None,
        bandwidth_reading=None,
        domain_id="",
        installation=None,
        bandwidth_incomplete_since=now,
    )
    AccountUsageState.objects.filter(account=account).update(
        service_id_snapshot=account.service_id,
        customer_id_snapshot=account.service.customer_id,
        server_id_snapshot=account.server_id,
    )
    state = AccountUsageState.objects.get(account=account)
    UsageInterval.objects.create(
        account=account,
        owner_scope=state.owner_scope,
        server_id=account.server_id,
        server_id_snapshot=account.server_id,
        started_at=now,
        domain_id=previous.domain_id if previous.server_id_snapshot == account.server_id else "",
        installation=previous.installation if previous.server_id_snapshot == account.server_id else None,
    )


def move_interval(account_id: UUID, server_id: UUID) -> None:
    now = timezone.now()
    state = AccountUsageState.objects.filter(account_id=account_id).first()
    if state is None:
        return
    UsageInterval.objects.filter(account_id=account_id, ended_at__isnull=True).update(ended_at=now)
    UsageInterval.objects.create(
        account_id=account_id,
        owner_scope=state.owner_scope,
        server_id=server_id,
        server_id_snapshot=server_id,
        started_at=now,
    )
    AccountUsageState.objects.filter(pk=state.pk).update(
        server_id_snapshot=server_id,
        gauge_not_before=now,
        disk_reading=None,
        domain_id="",
        installation=None,
        bandwidth_incomplete_since=now,
    )


def invalidate_gauge(account_id: UUID) -> None:
    """The caller holds the business account lock in its terminal transaction."""
    account = VirtualminAccount.objects.select_related("service").filter(pk=account_id).first()
    if account is None:
        return
    state = current_state(account)
    AccountUsageState.objects.filter(pk=state.pk).update(gauge_not_before=timezone.now(), disk_reading=None)


def rebind_created_account(account_id: UUID) -> None:
    """A verified recreation can replace the native ID on the same node."""
    if AccountUsageState.objects.filter(account_id=account_id).exists():
        account = VirtualminAccount.objects.get(pk=account_id)
        move_interval(account_id, account.server_id)


@dataclass(frozen=True)
class AccountCapture:
    scope: UUID
    service: int
    customer: int
    epoch: int


def capture(server: VirtualminServer) -> dict[UUID, AccountCapture]:
    captures = {}
    candidates = (
        VirtualminAccount.objects.filter(
            Q(server=server, status__in=("active", "suspended")) | Q(usage_intervals__server=server)
        )
        .distinct()
        .select_related("service")
    )
    for account in candidates:
        state = current_state(account)
        captures[account.pk] = AccountCapture(
            state.owner_scope, account.service_id, account.service.customer_id, account.chain_epoch
        )
    return captures


def record_failure(server_id: UUID, reason: str) -> None:
    NodeUsageSyncState.objects.update_or_create(
        server_id=server_id, defaults={"outcome": reason, "last_attempt_at": timezone.now()}
    )


@transaction.atomic
def publish_snapshot(  # noqa: C901, PLR0912, PLR0915  # Independent publication guards
    server_id: UUID, payload: object, captured: dict[UUID, AccountCapture], *, token: UUID | None = None
) -> int:
    if (
        not enabled()
        or not isinstance(payload, dict)
        or type(payload.get("version")) is not int
        or payload.get("version") != 1
    ):
        return 0
    installation = UUID(str(payload.get("installation")))
    observed = timestamp(payload.get("observed_at"))
    records = payload.get("records")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("Usage records are missing")
    published = 0
    attempt = token or uuid4()
    # Business writers take the account lock first. Keep that order even for
    # source-node intervals belonging to accounts now hosted elsewhere.
    list(VirtualminAccount.objects.select_for_update(no_key=True).filter(pk__in=captured).order_by("pk"))
    if token is not None:
        from .virtualmin_usage_tasks import transport_identity  # noqa: PLC0415

        claim = (
            NodeUsageSyncState.objects.select_for_update()
            .filter(server_id=server_id, token=token, lease_until__gt=timezone.now())
            .first()
        )
        if claim is None or claim.input_identity != transport_identity(VirtualminServer.objects.get(pk=server_id)):
            return 0
    for account_id, expected in captured.items():
        with transaction.atomic():
            account = (
                VirtualminAccount.objects.select_for_update(of=("self",), no_key=True)
                .select_related("service")
                .filter(pk=account_id)
                .first()
            )
            if account is None or account.server_id != server_id or account_blocks_reconcile(account):
                continue
            state = current_state(account)
            if (
                AccountCapture(state.owner_scope, account.service_id, account.service.customer_id, account.chain_epoch)
                != expected
            ):
                continue
            matches = [
                row
                for row in records
                if isinstance(row, dict)
                and row.get("domain") == account.domain
                and row.get("username") == account.virtualmin_username
                and row.get("present") is not False
            ]
            if len(matches) != 1:
                continue
            row = matches[0]
            if row.get("present") is False:
                continue
            try:
                domain_id = str(row["domain_id"])
                if not domain_id.isascii() or not domain_id.isdigit() or len(domain_id) > MAX_DOMAIN_ID:
                    raise ValueError("Invalid domain identity")
                if state.domain_id and (state.domain_id != domain_id or state.installation != installation):
                    raise ValueError("Node binding changed")
                identity_at = timestamp(row.get("identity_observed_at", row.get("scan_started_at")))
                if not state.domain_id and (identity_at < state.gauge_not_before or identity_at > observed):
                    continue
                # Identity is useful for traffic even when a filesystem/DB walk
                # is unsupported. A missing gauge must not erase that binding.
                state.domain_id, state.installation = domain_id, installation
                state.save(update_fields=["domain_id", "installation", "updated_at"])
                UsageInterval.objects.filter(account=account, ended_at__isnull=True).update(
                    domain_id=domain_id, installation=installation
                )
                start, finish = timestamp(row.get("scan_started_at")), timestamp(row.get("scan_finished_at"))
                if start < state.gauge_not_before or finish < start or finish > observed:
                    continue
                files, database = integer(row.get("disk_files_bytes")), integer(row.get("disk_db_bytes"))
                databases = integer(row.get("databases"))
                mailboxes = integer(row["mailboxes"]) if row.get("mailboxes") is not None else None
                if (
                    files + database > MAX_VALUE
                    or (files + database) // MIB > MAX_PROJECTION
                    or databases > MAX_PROJECTION
                    or (mailboxes is not None and mailboxes > MAX_PROJECTION)
                ):
                    raise ValueError("Disk total exceeds protocol bound")
            except (ValueError, KeyError, TypeError):
                continue
            period_start, period_end = month(observed)
            reading, created = UsageReading.objects.get_or_create(
                account=account,
                sync_token=attempt,
                defaults={
                    "owner_scope": state.owner_scope,
                    "server_id_snapshot": server_id,
                    "chain_epoch": account.chain_epoch,
                    "taken_at": finish,
                    "scan_started_at": start,
                    "disk_files_bytes": files,
                    "disk_db_bytes": database,
                    "disk_total_bytes": files + database,
                    "databases": databases,
                    "mailboxes": mailboxes,
                    "period_start": period_start,
                    "period_end": period_end,
                    "period_timezone": settings.TIME_ZONE,
                },
            )
            if not created or (state.disk_reading is not None and state.disk_reading.taken_at >= finish):
                continue
            state.disk_reading = reading
            state.domain_id, state.installation = domain_id, installation
            state.save(update_fields=["disk_reading", "domain_id", "installation", "updated_at"])
            UsageInterval.objects.filter(account=account, ended_at__isnull=True).update(
                domain_id=domain_id, installation=installation
            )
            VirtualminAccount.objects.filter(pk=account.pk).update(current_disk_usage_mb=(files + database) // MIB)
            Service.objects.filter(pk=account.service_id, customer_id=expected.customer).update(
                disk_usage_mb=(files + database) // MIB,
                databases_used=databases,
                **({"email_accounts_used": mailboxes} if mailboxes is not None else {}),
            )
            published += 1
    publish_segments(server_id, installation, records, observed, attempt, captured)
    if (
        token is not None
        and not NodeUsageSyncState.objects.filter(
            server_id=server_id, token=token, lease_until__gt=timezone.now()
        ).exists()
    ):
        transaction.set_rollback(True)
        return 0
    return published


def publish_segments(  # noqa: C901, PLR0913  # Independent source and ownership guards
    server_id: UUID,
    installation: UUID,
    records: list[object],
    observed: datetime,
    attempt: UUID,
    captured: dict[UUID, AccountCapture],
) -> None:
    """Only canonical node/owner intersections can contribute to a monthly total."""
    start, end = month(observed)
    key = start.isoformat()
    changed = set()
    for row in records:
        if not isinstance(row, dict) or not isinstance(row.get("segments"), list):
            continue
        for segment in row["segments"]:
            try:
                identifier = UUID(str(segment["id"]))
                amount = integer(segment["bytes"])
                lower, upper = timestamp(segment["start"]), timestamp(segment["end"])
            except (ValueError, TypeError, KeyError):
                continue
            with transaction.atomic():
                interval = UsageInterval.objects.filter(
                    pk=identifier, server_id=server_id, account_id__in=captured
                ).first()
                if interval is None:
                    continue
                account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=interval.account_id)
                state = current_state(account)
                interval = UsageInterval.objects.select_for_update().filter(pk=identifier, server_id=server_id).first()
                if interval is None:
                    continue
                expected = AccountCapture(
                    state.owner_scope, account.service_id, account.service.customer_id, account.chain_epoch
                )
                if (
                    interval.owner_scope != state.owner_scope
                    or captured.get(account.pk) != expected
                    or account_blocks_reconcile(account)
                    or interval.installation != installation
                    or not interval.domain_id
                    or interval.domain_id != row.get("domain_id")
                ):
                    continue
                if lower != max(start, interval.started_at, state.owner_started_at) or upper != min(
                    end, interval.ended_at or observed, observed
                ):
                    continue
                if segment.get("complete") is not True:
                    if state.bandwidth_reading is None or observed >= state.bandwidth_reading.taken_at:
                        AccountUsageState.objects.filter(pk=state.pk).update(bandwidth_incomplete_since=observed)
                    continue
                previous = interval.totals.get(key)
                if previous and timestamp(previous["through"]) > upper:
                    continue
                interval.totals = {
                    **interval.totals,
                    key: {"bytes": amount, "through": upper.isoformat(), "complete": True},
                }
                interval.save(update_fields=["totals", "updated_at"])
                changed.add(account.pk)
    for account_id in changed:
        publish_bandwidth(account_id, observed, attempt)


def publish_bandwidth(account_id: UUID, observed: datetime, attempt: UUID) -> None:
    account = VirtualminAccount.objects.select_related("service").get(pk=account_id)
    state = current_state(account)
    start, end = month(observed)
    key = start.isoformat()
    if not state.owner_start_known and state.owner_started_at >= start:
        return  # First-month history predating instrumentation cannot be reconstructed.
    parts = list(
        UsageInterval.objects.filter(
            account=account, owner_scope=state.owner_scope, started_at__lt=min(end, observed)
        ).filter(transaction_time_filter(start))
    )
    if not parts or any(
        key not in part.totals or (part.ended_at and timestamp(part.totals[key]["through"]) != min(end, part.ended_at))
        for part in parts
    ):
        return
    total = integer(sum(integer(part.totals[key]["bytes"]) for part in parts))
    if total // MIB > MAX_PROJECTION:
        return
    open_times = [timestamp(part.totals[key]["through"]) for part in parts if part.ended_at is None]
    as_of = min(open_times) if open_times else observed
    if state.bandwidth_reading is not None and state.bandwidth_reading.taken_at >= as_of:
        return
    reading, created = UsageReading.objects.get_or_create(
        account=account,
        sync_token=uuid5(attempt, "bandwidth"),
        defaults={
            "owner_scope": state.owner_scope,
            "server_id_snapshot": account.server_id,
            "chain_epoch": account.chain_epoch,
            "taken_at": as_of,
            "period_start": start,
            "period_end": end,
            "period_timezone": settings.TIME_ZONE,
            "bandwidth_bytes": total,
            "bandwidth_complete": True,
        },
    )
    if created:
        state.bandwidth_reading = reading
        state.bandwidth_incomplete_since = None
        state.save(update_fields=["bandwidth_reading", "bandwidth_incomplete_since", "updated_at"])
        VirtualminAccount.objects.filter(pk=account.pk).update(current_bandwidth_usage_mb=total // MIB)
        Service.objects.filter(pk=account.service_id).update(bandwidth_usage_mb=total // MIB)


def transaction_time_filter(start: datetime) -> Q:
    return Q(ended_at__isnull=True) | Q(ended_at__gt=start)


def public_usage(service: Service) -> dict[str, object]:
    """Local-only selector; no request contacts a node or initializes observations."""
    result: dict[str, object] = {
        "disk_usage_gb": None,
        "bandwidth_usage_gb": None,
        "disk_usage_percentage": None,
        "bandwidth_usage_percentage": None,
        "databases_used": None,
        "email_accounts_used": None,
        "usage_as_of": None,
        "usage_age_hours": None,
        "usage_state": "unknown",
        "bandwidth_complete": False,
        "bandwidth_state": "unknown",
        "bandwidth_age_hours": None,
    }
    account = VirtualminAccount.objects.filter(service=service).first()
    if account is None:
        return result
    state = (
        AccountUsageState.objects.select_related("disk_reading", "bandwidth_reading").filter(account=account).first()
    )
    if state is None or (state.service_id_snapshot, state.customer_id_snapshot, state.server_id_snapshot) != (
        service.pk,
        service.customer_id,
        account.server_id,
    ):
        return result
    failed_poll = NodeUsageSyncState.objects.filter(server_id=account.server_id, outcome="unavailable").first()
    reading = state.disk_reading
    if (
        reading
        and reading.owner_scope == state.owner_scope
        and reading.chain_epoch == account.chain_epoch
        and reading.scan_started_at is not None
        and reading.scan_started_at >= state.gauge_not_before
        and reading.disk_total_bytes is not None
        and reading.disk_files_bytes is not None
        and reading.disk_db_bytes is not None
    ):
        result.update(
            {
                "disk_usage_gb": round(reading.disk_total_bytes / MIB / 1024, 2),
                "disk_usage_percentage": round(
                    reading.disk_total_bytes / MIB / 1024 / service.service_plan.disk_space_gb * 100, 1
                )
                if service.service_plan.disk_space_gb
                else None,
                "databases_used": reading.databases,
                "email_accounts_used": reading.mailboxes,
                "usage_as_of": reading.taken_at.isoformat(),
                "usage_age_hours": max(0, int((timezone.now() - reading.taken_at).total_seconds() // 3600)),
                "usage_state": "stale"
                if timezone.now() - reading.taken_at >= STALE_AFTER
                or (failed_poll and failed_poll.last_attempt_at and failed_poll.last_attempt_at > reading.taken_at)
                else "fresh",
                "disk_files_gb": round(reading.disk_files_bytes / MIB / 1024, 2),
                "disk_db_gb": round(reading.disk_db_bytes / MIB / 1024, 2),
            }
        )
    result["bandwidth_state"] = "partial"
    bandwidth = state.bandwidth_reading
    if (
        bandwidth
        and bandwidth.bandwidth_bytes is not None
        and bandwidth.owner_scope == state.owner_scope
        and (bandwidth.period_start, bandwidth.period_end) == month(timezone.now())
        and bandwidth.period_timezone == settings.TIME_ZONE
        and state.bandwidth_incomplete_since is None
    ):
        result.update(
            {
                "bandwidth_usage_gb": round(bandwidth.bandwidth_bytes / MIB / 1024, 2),
                "bandwidth_complete": True,
                "bandwidth_as_of": bandwidth.taken_at.isoformat(),
                "usage_period_start": bandwidth.period_start.isoformat(),
                "bandwidth_age_hours": max(0, int((timezone.now() - bandwidth.taken_at).total_seconds() // 3600)),
                "usage_period_end": bandwidth.period_end.isoformat(),
                "usage_period_timezone": bandwidth.period_timezone,
                "bandwidth_state": "stale"
                if timezone.now() - bandwidth.taken_at >= STALE_AFTER
                or (failed_poll and failed_poll.last_attempt_at and failed_poll.last_attempt_at > bandwidth.taken_at)
                else "fresh",
                "bandwidth_usage_percentage": round(
                    bandwidth.bandwidth_bytes / MIB / 1024 / service.service_plan.bandwidth_gb * 100, 1
                )
                if service.service_plan.bandwidth_gb
                else None,
            }
        )
    return result


def usage_history(service: Service, days: int = 30) -> dict[str, object]:
    """History is selected by the current owner scope, never by account alone."""
    state = AccountUsageState.objects.filter(
        account__service=service, service_id_snapshot=service.pk, customer_id_snapshot=service.customer_id
    ).first()
    result: dict[str, object] = {
        "disk_usage_trend": [],
        "bandwidth_usage_trend": [],
        "disk_sparkline": "",
        "uptime_percentage": None,
    }
    if state is None:
        return result
    readings = UsageReading.objects.filter(
        account=state.account,
        owner_scope=state.owner_scope,
        taken_at__gte=timezone.now() - timedelta(days=min(max(days, 1), 90)),
        disk_total_bytes__isnull=False,
    ).order_by("taken_at")
    # One point per operator calendar day bounds response size independently of
    # polling/retries. Keep the actual sample time in the API.
    daily = {}
    zone = ZoneInfo(settings.TIME_ZONE)
    for reading in readings:
        daily[reading.taken_at.astimezone(zone).date()] = reading
    points = list(daily.values())
    result["disk_usage_trend"] = [
        {"taken_at": item.taken_at.isoformat(), "value": round(integer(item.disk_total_bytes) / MIB / 1024, 3)}
        for item in points
    ]
    if points:
        maximum = max(integer(item.disk_total_bytes) for item in points) or 1
        result["disk_sparkline"] = " ".join(
            f"{index * 300 / max(len(points) - 1, 1):.1f},{60 - integer(item.disk_total_bytes) / maximum * 55:.1f}"
            for index, item in enumerate(points)
        )
    return result


def node_usage_status(server_id: UUID | None = None) -> list[dict[str, object]]:
    """Usage attention has a six-hour clock, independently of node health."""
    if not enabled():
        return []
    servers = VirtualminServer.objects.filter(status="active")
    if server_id is not None:
        servers = servers.filter(pk=server_id)
    result = []
    for server in servers:
        accounts = VirtualminAccount.objects.filter(server=server, status__in=("active", "suspended")).select_related(
            "usage_state__disk_reading"
        )
        missing = 0
        for account in accounts:
            state = getattr(account, "usage_state", None)
            reading = state.disk_reading if state else None
            as_of = reading.taken_at if reading else (state.gauge_not_before if state else account.created_at)
            if timezone.now() - as_of >= STALE_AFTER:
                missing += 1
        sync = NodeUsageSyncState.objects.filter(server=server).first()
        result.append(
            {
                "server": server,
                "attention": bool(missing or (sync and sync.outcome in {"missing_accounts", "unassigned_accounts"})),
                "stale_accounts": missing,
                "last_attempt": sync.last_attempt_at if sync else None,
                "last_success": sync.last_success_at if sync else None,
                "outcome": sync.outcome if sync else "unknown",
            }
        )
    return result
