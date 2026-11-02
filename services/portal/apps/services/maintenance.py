"""Validate customer-only maintenance receipts and format display data without business state."""

from __future__ import annotations

from datetime import timedelta
from typing import TypedDict, cast
from uuid import UUID

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError
from apps.common.localisation import DisplayLocalisation, format_localised_date


class MaintenanceWindow(TypedDict):
    id: str
    kind: str
    status: str
    starts_at: str
    ends_at: str
    started_at: str | None
    finished_at: str | None
    expects_downtime: bool
    expected_downtime_minutes: int | None
    customer_note: str
    public_outcome: str
    completion_source: str
    was_overrun: bool
    service_ids: list[int]


class MaintenanceSummary(TypedDict):
    windows: list[MaintenanceWindow]
    last_completed: MaintenanceWindow | None


def _timestamp(value: object, *, optional: bool = False) -> bool:
    if value is None:
        return optional
    try:
        parsed = parse_datetime(value) if isinstance(value, str) else None
    except ValueError:
        return False
    return parsed is not None and timezone.is_aware(parsed)


def _valid_window(value: object, *, completed: bool = False) -> bool:
    if not isinstance(value, dict) or set(value) != MaintenanceWindow.__required_keys__:
        return False
    try:
        UUID(value["id"]) if isinstance(value["id"], str) else None
    except ValueError:
        return False
    if not isinstance(value["id"], str):
        return False
    statuses = {"completed", "failed"} if completed else {"scheduled", "running", "overran"}
    return (
        isinstance(value["kind"], str)
        and value["kind"] in {"reboot", "panel_update", "emergency"}
        and isinstance(value["status"], str)
        and value["status"] in statuses
        and _timestamp(value["starts_at"])
        and _timestamp(value["ends_at"])
        and _timestamp(value["started_at"], optional=True)
        and _timestamp(value["finished_at"], optional=not completed)
        and type(value["expects_downtime"]) is bool
        and type(value["was_overrun"]) is bool
        and (
            value["expected_downtime_minutes"] is None
            or (type(value["expected_downtime_minutes"]) is int and value["expected_downtime_minutes"] >= 0)
        )
        and isinstance(value["customer_note"], str)
        and isinstance(value["public_outcome"], str)
        and isinstance(value["completion_source"], str)
        and value["completion_source"] in {"job", "operator", ""}
        and isinstance(value["service_ids"], list)
        and bool(value["service_ids"])
        and all(type(service_id) is int and service_id > 0 for service_id in value["service_ids"])
    )


def maintenance_receipt(response: object, *, service_id: int | None = None) -> MaintenanceSummary:
    """Unknown/malformed data is unavailable, never a successful empty snapshot."""
    data = response.get("data") if isinstance(response, dict) else None
    summary = data.get("maintenance") if isinstance(data, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("success") is not True
        or not isinstance(summary, dict)
        or set(summary) != {"windows", "last_completed"}
        or not isinstance(summary["windows"], list)
        or not all(_valid_window(item) for item in summary["windows"])
        or (summary["last_completed"] is not None and not _valid_window(summary["last_completed"], completed=True))
    ):
        raise PlatformAPIError("Maintenance information is unavailable")
    result = cast(MaintenanceSummary, summary)
    visible = [*result["windows"], *([result["last_completed"]] if result["last_completed"] else [])]
    if service_id is not None and any(service_id not in item["service_ids"] for item in visible):
        raise PlatformAPIError("Maintenance information is unavailable")
    return result


def maintenance_heading(window: MaintenanceWindow) -> str:
    return {
        "scheduled": _("Scheduled maintenance for your hosting"),
        "running": _("Maintenance is in progress"),
        "overran": _("Maintenance is taking longer than planned"),
        "completed": _("Maintenance completed"),
        "failed": _("Maintenance did not complete as planned"),
    }[window["status"]]


def maintenance_period(window: MaintenanceWindow, policy: DisplayLocalisation) -> str:
    return _("%(start)s - %(end)s (%(zone)s)") % {
        "start": format_localised_date(window["starts_at"], policy, "datetime"),
        "end": format_localised_date(window["ends_at"], policy, "datetime"),
        "zone": policy.timezone,
    }


def maintenance_presentation(summary: MaintenanceSummary, policy: DisplayLocalisation) -> dict[str, object]:
    """Only safe public receipt fields enter the shared attention partial."""
    windows = []
    kinds = {
        "reboot": _("A restart of a server supporting your hosting services"),
        "panel_update": _("Updates to a server supporting your hosting services"),
        "emergency": _("Emergency work on a server supporting your hosting services"),
    }
    for window in summary["windows"]:
        impact = _("Brief unavailability may occur.")
        if not window["expects_downtime"]:
            impact = _("No downtime is expected.")
        elif window["expected_downtime_minutes"] is not None:
            impact = _("Expected unavailability: up to %(minutes)d minutes.") % {
                "minutes": window["expected_downtime_minutes"]
            }
        windows.append(
            {
                "heading": maintenance_heading(window),
                "period": maintenance_period(window, policy),
                "description": kinds[window["kind"]],
                "impact": impact,
                "note": window["customer_note"],
                "variant": "warning" if window["status"] == "overran" else "info",
            }
        )
    completed = summary["last_completed"]
    outcome: dict[str, object] | None = None
    if completed:
        finished = parse_datetime(completed["finished_at"] or "")
        now = timezone.now()
        if finished is not None and now - timedelta(hours=24) < finished <= now:
            outcome = {
                "heading": maintenance_heading(completed),
                "finished": format_localised_date(finished, policy, "datetime"),
                "zone": policy.timezone,
                "text": completed["public_outcome"],
                "operator_confirmed": completed["completion_source"] == "operator",
                "was_overrun": completed["was_overrun"],
            }
    return {"maintenance_windows": windows, "maintenance_outcome": outcome}
