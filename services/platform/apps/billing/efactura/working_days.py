"""Romanian working-day arithmetic for RO e-Factura submission deadlines.

OUG 89/2025 (effective 1 Jan 2026) changed the e-Factura submission deadline from 5 calendar days
to 5 WORKING days from the invoice issue date (Art. 10 para. 7), with the term computed per
Regulation (EEC, Euratom) No. 1182/71. Working days skip Saturdays, Sundays, and Romanian public
holidays — including the moveable Orthodox Easter and Pentecost — via the `holidays` library.
"""

from __future__ import annotations

import datetime
from zoneinfo import ZoneInfo

import holidays

ROMANIA_TZ = ZoneInfo("Europe/Bucharest")

# date.weekday() returns 0=Monday..6=Sunday; values < this are working weekdays (Mon-Fri).
_SATURDAY = 5


def add_working_days(start: datetime.date, working_days: int) -> datetime.date:
    """Return the date `working_days` Romanian working days after `start` (start exclusive).

    Skips Saturdays, Sundays and Romanian public holidays. A non-positive `working_days` returns
    `start` unchanged. The holiday calendar spans `start`'s year and the next so a year-end deadline
    that rolls into January still sees January's holidays.
    """
    if working_days <= 0:
        return start
    cal = holidays.Romania(years=range(start.year, start.year + 2))  # type: ignore[attr-defined]  # no stubs
    result = start
    remaining = working_days
    while remaining > 0:
        result += datetime.timedelta(days=1)
        if result.weekday() < _SATURDAY and result not in cal:  # Mon-Fri and not a public holiday
            remaining -= 1
    return result


def submission_deadline_datetime(issued_at: datetime.datetime, working_days: int) -> datetime.datetime:
    """Romanian working-day submission deadline as an aware datetime (end of the deadline day in
    Romania time).

    `issued_at` is first converted to the Romanian LOCAL calendar date so the day boundary is RO
    time, not UTC — an invoice issued at 23:30 UTC counts from the next Romanian day.
    """
    issue_date = issued_at.astimezone(ROMANIA_TZ).date()
    deadline_date = add_working_days(issue_date, working_days)
    return datetime.datetime.combine(deadline_date, datetime.time.max, tzinfo=ROMANIA_TZ)
