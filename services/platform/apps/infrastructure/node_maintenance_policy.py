"""Explicit operator wall times and permitted weekly maintenance intervals."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy


def parse_staff_datetime(value: str, zone_name: str) -> datetime:
    """Resolve a staff-entered ISO value in the policy timezone."""
    try:
        value_at = datetime.fromisoformat(value)
        zone = ZoneInfo(zone_name)
    except ValueError as exc:
        raise ValidationError(_("Enter a valid date and time.")) from exc
    if timezone.is_aware(value_at):
        return value_at.astimezone(UTC)
    candidates: set[datetime] = set()
    for fold in (0, 1):
        candidate = value_at.replace(tzinfo=zone, fold=fold).astimezone(UTC)
        if candidate.astimezone(zone).replace(tzinfo=None) == value_at:
            candidates.add(candidate)
    if not candidates:
        raise ValidationError(_("This local time does not exist because the clocks change. Choose another time."))
    if len(candidates) != 1:
        raise ValidationError(_("This local time occurs twice. Include an explicit UTC offset to choose which one."))
    return candidates.pop()


def validate_policy_interval(policy: NodeMaintenancePolicy, starts_at: datetime, ends_at: datetime) -> None:
    """Validate a proposed interval against its explicitly configured policy."""
    policy.clean()
    if timezone.is_naive(starts_at) or timezone.is_naive(ends_at):
        raise ValidationError(_("Maintenance times must include a timezone."))
    starts_at, ends_at = starts_at.astimezone(UTC), ends_at.astimezone(UTC)
    if ends_at <= starts_at:
        raise ValidationError(_("Maintenance must end after it starts."))
    local_day = starts_at.astimezone(ZoneInfo(policy.timezone)).date()
    for interval_day in (local_day - timedelta(days=1), local_day):
        if interval_day.weekday() not in policy.weekdays:
            continue
        end_day = interval_day + timedelta(days=int(policy.ends_time < policy.starts_time))
        permitted_start = parse_staff_datetime(
            datetime.combine(interval_day, policy.starts_time).isoformat(), policy.timezone
        )
        permitted_end = parse_staff_datetime(datetime.combine(end_day, policy.ends_time).isoformat(), policy.timezone)
        if permitted_start <= starts_at < ends_at <= permitted_end:
            return
    raise ValidationError(_("The entire window must fit one of this server's permitted maintenance intervals."))
