"""End portal sessions from the server: one person's, everyone's, or every session live in a window.

    manage.py revoke_portal_sessions --user someone@example.ro --reason "Lost laptop"
    manage.py revoke_portal_sessions --all --reason "Rolled back"
    manage.py revoke_portal_sessions --active-between 2026-10-29T10:00+02:00 2026-10-29T11:00+02:00 \
        --reason "Incident 42"

``--active-between`` selects every session whose life overlaps the window: opened by its end and
still live at its start (idle only moves forward on a live session, so its idle deadline bounds its
whole life). The selection is taken when the command starts: a session opened while it runs
survives, so for an incident disable the account or reset its password first. A revoked session is
refused at its next call to Platform (ADR-0017 section 5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db.models import QuerySet
from django.utils import timezone

from apps.users import portal_sessions
from apps.users.management.operator import operator_name
from apps.users.models import PortalSession, User


def _person(value: str) -> User:
    user = User.objects.filter(pk=int(value)).first() if value.isdigit() else None
    user = user or User.objects.filter(email__iexact=value.strip()).first()
    if user is None:
        raise CommandError(f"No account with the email or id {value}.")
    return user


def _moment(value: str) -> datetime:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CommandError(f"{value} is not an ISO 8601 time.") from exc
    if timezone.is_naive(moment):
        raise CommandError(f"{value} has no time zone; give one, for example +02:00 or Z.")
    return moment


def _count(sessions: int, people: int) -> str:
    return f"{sessions} session{'' if sessions == 1 else 's'} for {people} {'person' if people == 1 else 'people'}"


class Command(BaseCommand):
    help = "End portal sessions (audited operator action)."

    def add_arguments(self, parser: CommandParser) -> None:
        selector = parser.add_mutually_exclusive_group(required=True)
        selector.add_argument("--user", help="The person's email address or account id.")
        selector.add_argument("--all", action="store_true", help="Every live session.")
        selector.add_argument(
            "--active-between", nargs=2, metavar=("FROM", "TO"), help="ISO 8601 times with a time zone."
        )
        parser.add_argument("--reason", required=True, help="Why, for the audit trail.")
        parser.add_argument("--dry-run", action="store_true", help="List what would end, and end nothing.")

    def handle(self, *args: Any, **options: Any) -> None:
        reason = str(options["reason"]).strip()
        if not reason:
            raise CommandError("Give a reason; it is recorded in the audit trail.")
        rows, selector = self._selection(options)
        targets = list(rows.select_related("user").order_by("created_at"))  # the snapshot
        if options["dry_run"]:
            self._report("Would end", targets)
            return
        from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: cross-app, deferred

        ended: list[PortalSession] = []
        completed = False
        try:
            # extend keeps the rows appended before a failure, which the audit below counts
            ended.extend(row for row in targets if portal_sessions.end(row, portal_sessions.REASON_OPERATOR))
            completed = True
        finally:
            # Written even when a failure stops the run, so the sessions already ended name who ended them.
            AuditService.log_simple_event(
                "portal_sessions_revoked",
                description="An operator ended portal sessions",
                actor_type="system",
                metadata={
                    "operator": operator_name(),
                    "selector": selector,
                    "reason": reason,
                    "sessions": len(ended),
                    "people": len({row.user_id for row in ended}),
                    "completed": completed,
                },
            )
        self._report("Ended", ended)

    def _selection(self, options: dict[str, Any]) -> tuple[QuerySet[PortalSession], str]:
        now = timezone.now()
        live = PortalSession.objects.filter(revoked_at__isnull=True, expires_at__gt=now, idle_deadline__gt=now)
        if options["user"]:
            user = _person(str(options["user"]))
            return live.filter(user=user), f"user:{user.pk}"
        if options["all"]:
            return live, "all"
        start, end = (_moment(value) for value in options["active_between"])
        if start > end:
            raise CommandError("The window ends before it starts.")
        overlap = live.filter(created_at__lte=end, idle_deadline__gte=start, expires_at__gte=start)
        return overlap, f"active-between:{start.isoformat()}/{end.isoformat()}"

    def _report(self, verb: str, rows: list[PortalSession]) -> None:
        people = sorted({row.user.email for row in rows})
        self.stdout.write(f"{verb} {_count(len(rows), len(people))}.")
        for email in people:
            self.stdout.write(f"  {email}")
