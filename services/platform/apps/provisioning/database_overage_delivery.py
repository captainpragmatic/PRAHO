"""The two notices of a database over-allowance episode: day 0 (writes stay on until the deadline) and day 14
(writes are now held). Each goes by email and on the episode's support ticket, once per episode.

A notice is checked again just before the provider sends it: the episode is still open and in the state the
notice describes, and the owner, recipient, service and account are what they were. "Accepted" means the
provider accepted the email, not that it was queued. A crash between the provider's acceptance and its record
can repeat an email; that rare repeat is accepted.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone, translation
from django.utils.translation import gettext as _

from .database_overage_models import DatabaseOverageEpisode, DatabaseOverageNotice, EpisodeState, NoticeKind
from .database_overage_service import allowance_bytes, audit_episode, grace_period

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.notifications.models import EmailLog

logger = logging.getLogger(__name__)

TEMPLATES = {NoticeKind.DAY0: "database_overage_day0", NoticeKind.DAY14: "database_overage_day14"}
ACCEPTED_EMAIL_STATES = frozenset({"sent", "delivered", "opened", "clicked", "bounced", "complained", "unsubscribed"})

# Default bodies; an operator's edited template is kept as it is.
_DEFAULTS = {
    (NoticeKind.DAY0, "en"): (
        "Your databases are over your hosting allowance",
        "The databases of {{ service_name }} take your hosting over its {{ allowance }} allowance"
        " ({{ usage }} used).\nDatabase writes stay enabled until {{ deadline }}. If the account is still over"
        " its allowance then, database writes are held: you can still read, delete and drop data.\nDelete data"
        " you no longer need, upgrade your plan, or reply to the support ticket we opened for you.",
    ),
    (NoticeKind.DAY0, "ro"): (
        "Bazele de date depășesc limita găzduirii",
        "Bazele de date ale {{ service_name }} depășesc limita de {{ allowance }} a găzduirii"
        " ({{ usage }} folosiți).\nScrierea în baze de date rămâne permisă până la {{ deadline }}. Dacă atunci"
        " contul depășește încă limita, scrierea în baze de date este blocată: puteți în continuare să citiți,"
        " să ștergeți date și să eliminați tabele.\nȘtergeți datele de care nu mai aveți nevoie, treceți la un"
        " plan superior sau răspundeți la tichetul de asistență deschis pentru dumneavoastră.",
    ),
    (NoticeKind.DAY14, "en"): (
        "Database writes are now held",
        "The databases of {{ service_name }} are still over its {{ allowance }} allowance ({{ usage }} used),"
        " so database writes are now held. Reading, deleting and dropping data still work.\nDeleting rows doesn't"
        " shrink a database's files: drop tables you no longer need, upgrade your plan, or reply to your support"
        " ticket to ask for a short write window.",
    ),
    (NoticeKind.DAY14, "ro"): (
        "Scrierea în baze de date este blocată",
        "Bazele de date ale {{ service_name }} depășesc în continuare limita de {{ allowance }}"
        " ({{ usage }} folosiți), așa că scrierea în baze de date este acum blocată. Citirea, ștergerea datelor"
        " și eliminarea tabelelor funcționează în continuare.\nȘtergerea rândurilor nu micșorează fișierele"
        " bazei de date: eliminați tabelele de care nu mai aveți nevoie, treceți la un plan superior sau"
        " răspundeți la tichetul de asistență pentru o fereastră scurtă de scriere.",
    ),
}


def setup_overage_notices() -> dict[str, str]:
    """Install the notice templates idempotently; existing operator template content is preserved."""
    from apps.notifications.models import EmailTemplate  # noqa: PLC0415

    created = 0
    for (kind, locale), (subject, body) in _DEFAULTS.items():
        _template, made = EmailTemplate.objects.get_or_create(
            key=TEMPLATES[kind],
            locale=locale,
            defaults={
                "category": "quota_warnings",
                "subject": subject,
                "body_text": body,
                # Paragraph for paragraph, as the warning templates: the text stays for clients without HTML.
                "body_html": "".join(f"<p>{paragraph}</p>" for paragraph in body.split("\n")),
            },
        )
        created += made
    return {"database_overage_notices": f"{created} created"}


def _gib(value: int | None) -> str:
    return "?" if value is None else f"{value / 1024**3:.2f} GiB"


def _recipient_hash(customer: Customer) -> str:
    from .hosting_warning_observation import recipient_hash  # noqa: PLC0415 -- One recipient digest contract.

    return recipient_hash(customer.primary_email or "")


def notice_refusal(
    episode: DatabaseOverageEpisode,
    kind: str,
    customer: Customer | None,
    *,
    notice: DatabaseOverageNotice | None = None,
) -> str | None:
    """Why this notice may not go out now, or None. Called before the send and again before the provider."""
    return _episode_refusal(episode, kind, notice) or _audience_refusal(episode, customer, notice)


def _episode_refusal(episode: DatabaseOverageEpisode, kind: str, notice: DatabaseOverageNotice | None) -> str | None:
    """The episode is open and in the state the notice describes (day 14: the very hold it reports)."""
    if episode.state == EpisodeState.CLOSED:
        return "overage_episode_closed"
    if kind == NoticeKind.DAY14 and (
        episode.state != EpisodeState.HELD
        or (
            notice is not None
            and (notice.held_digest, notice.hold_generation) != (episode.held_digest, episode.hold_generation)
        )
    ):
        return "overage_not_held"
    return None


def _audience_refusal(
    episode: DatabaseOverageEpisode, customer: Customer | None, notice: DatabaseOverageNotice | None
) -> str | None:
    """The owner, recipient, service and account are still the ones the notice was written for."""
    from apps.notifications.services import EmailSuppressionService  # noqa: PLC0415

    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    if (
        customer is None
        or customer.pk != episode.customer_id_snapshot
        or customer.status != "active"
        or customer.anonymized_at
        or customer.deleted_at
    ):
        return "overage_customer_unavailable"
    recipient = _recipient_hash(customer)
    if not recipient or (notice is not None and notice.recipient_hash != recipient):
        return "overage_recipient_changed"
    if EmailSuppressionService.is_suppressed(customer.primary_email, essential=True):
        return "overage_recipient_suppressed"
    account, service = episode.account, episode.service
    if account is None or service is None or service.status != "active" or account.status != "active":
        return "overage_service_inactive"
    owner_scope = AccountUsageState.objects.filter(account=account).values_list("owner_scope", flat=True).first()
    if service.customer_id != customer.pk or account.service_id != service.pk or owner_scope != episode.owner_scope:
        return "overage_ownership_changed"
    return None


def _ticket_text(kind: str, service_name: str) -> tuple[str, str]:
    if kind == NoticeKind.DAY0:
        return (
            _("Databases over the hosting allowance: %(service)s") % {"service": service_name},
            _(
                "The databases of %(service)s take this hosting account over its allowance. Database writes stay"
                " enabled for now; we emailed you the date after which they are held. Reply here if you need help."
            )
            % {"service": service_name},
        )
    return (
        _("Database writes held: %(service)s") % {"service": service_name},
        _(
            "Database writes for %(service)s are now held because its databases are still over the allowance."
            " Reading, deleting and dropping data still work. Reply here to ask for a short write window."
        )
        % {"service": service_name},
    )


def _replaceable(notice: DatabaseOverageNotice, recipient: str) -> bool:
    """Never accepted, and a fresh one may follow: refused at the provider boundary (provably unsent), or failed
    for good at an address staff have since corrected. Never sent again to the address that failed."""
    if notice.accepted_at is not None:
        return False
    if notice.refusal_reason:
        return True
    return _failed_for_good(notice.email_log) and recipient != notice.recipient_hash


def _failed_for_good(log: EmailLog | None) -> bool:
    """No provider took it and the email queue will never send it again; a retryable failure may still go out."""
    if log is None:
        return False
    response = log.provider_response if isinstance(log.provider_response, dict) else {}
    return log.status == "rejected" or (
        log.status == "failed"
        and (response.get("permanent_failure") is True or response.get("retry_exhausted") is True)
    )


def notice_due(episode: DatabaseOverageEpisode, kind: str) -> bool:
    """No notice of this kind yet, or one a fresh notice may replace."""
    from apps.customers.models import Customer  # noqa: PLC0415

    notice = DatabaseOverageNotice.objects.select_related("email_log").filter(episode=episode, kind=kind).first()
    if notice is None:
        return True
    customer = Customer.all_objects.filter(pk=episode.customer_id_snapshot).first()
    return _replaceable(notice, _recipient_hash(customer) if customer is not None else "")


def _store_notice(
    episode: DatabaseOverageEpisode,
    kind: str,
    customer: Customer,
    replaced: DatabaseOverageNotice | None,
    *,
    at: datetime,
) -> DatabaseOverageNotice:
    """The ticket entry, the notice row and its queued email, all in the caller's transaction."""
    from apps.customers.services import get_customer_locale  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415
    from apps.notifications.services import EmailService  # noqa: PLC0415
    from apps.tickets.services import add_system_comment, open_system_ticket  # noqa: PLC0415

    from .virtualmin_usage_models import AccountUsageState  # noqa: PLC0415

    service, account = episode.service, episode.account
    if service is None or account is None:
        raise ValueError("an overage notice needs the episode's service and account")
    locale = get_customer_locale(customer)
    day0 = DatabaseOverageNotice.objects.filter(episode=episode, kind=NoticeKind.DAY0).first()
    ticket = replaced.ticket if replaced is not None else None
    if ticket is None:  # a replacement already told the ticket
        with translation.override(locale):
            title, description = _ticket_text(kind, service.service_name)
        if kind == NoticeKind.DAY0 or day0 is None or day0.ticket is None:
            ticket = open_system_ticket(customer, title=title, description=description, related_service=service)
        else:
            ticket = day0.ticket
            add_system_comment(ticket, description)
    notice = replaced or DatabaseOverageNotice(episode=episode, kind=kind)
    if replaced is not None:
        logger.info(
            "⚠️ [DatabaseOverage] %s notice %s refused (%s); sending a replacement",
            kind,
            notice.pk,
            notice.refusal_reason,
        )
    notice.ticket, notice.recipient_hash, notice.refusal_reason = ticket, _recipient_hash(customer), ""
    notice.held_digest = episode.held_digest if kind == NoticeKind.DAY14 else ""
    notice.hold_generation = episode.hold_generation if kind == NoticeKind.DAY14 else 0
    notice.email_log = None
    notice.save()
    state = AccountUsageState.objects.select_related("disk_reading").filter(account=account).first()
    reading = state.disk_reading if state else None
    context = {
        "service_name": service.service_name,
        "allowance": _gib(allowance_bytes(service, account, at=at)),
        "usage": _gib(reading.disk_total_bytes if reading else None),
        "deadline": timezone.localtime(episode.deadline_at).strftime("%Y-%m-%d %H:%M"),
    }
    result = EmailService.send_template_email(
        template_key=TEMPLATES[NoticeKind(kind)],
        recipient=customer.primary_email,
        context=context,
        locale=locale,
        customer=customer,
        async_send=True,
        require_async=True,
        essential=True,
    )
    if not result.success or result.email_log_id is None:
        # Roll back the ticket and the notice with it; the next sweep tries again.
        raise ValueError("The database overage notice could not be stored: " + str(result.error))
    notice.email_log = log = EmailLog.objects.get(pk=result.email_log_id)
    notice.content = {
        "template_key": TEMPLATES[NoticeKind(kind)],
        "locale": locale,
        "subject": log.subject,
        "context": context,
        "body_sha256": hashlib.sha256(log.get_decrypted_body_text().encode()).hexdigest(),
    }
    notice.save(update_fields=["email_log", "content", "updated_at"])
    return notice


def send_notice(episode_id: UUID, kind: str, *, at: datetime | None = None) -> str:
    """Store one notice: its ticket entry and its email. Once per episode and kind, unless refused unsent."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    now = at or timezone.now()
    hint = DatabaseOverageEpisode.objects.filter(pk=episode_id).values("customer_id_snapshot").first()
    if hint is None:
        return "missing"
    with transaction.atomic():
        customer = (
            Customer.all_objects.select_for_update(of=("self",), no_key=True)
            .filter(pk=hint["customer_id_snapshot"])
            .first()
        )
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
        existing = DatabaseOverageNotice.objects.select_for_update().filter(episode=episode, kind=kind).first()
        if existing is not None and existing.email_log_id is not None:
            # Last in the dispatch order: a retry of its email can't start between this check and the replacement.
            existing.email_log = EmailLog.objects.select_for_update().get(pk=existing.email_log_id)
        if existing is not None and not _replaceable(
            existing, _recipient_hash(customer) if customer is not None else ""
        ):
            return "exists"
        if reason := notice_refusal(episode, kind, customer, notice=None):
            return reason
        if customer is None:
            return "overage_customer_unavailable"
        if kind == NoticeKind.DAY0:
            # A full grace period from the day the customer is told, and the email names that date.
            episode.deadline_at = max(episode.deadline_at, now + grace_period())
            episode.save(update_fields=["deadline_at", "updated_at"])
        _store_notice(episode, kind, customer, existing, at=now)
    logger.info("✅ [DatabaseOverage] %s notice stored for episode %s", kind, episode_id)
    return "sent"


def _orphan_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    """An email that is not a notice passes; a notice email with no notice record never goes out."""
    from apps.notifications.delivery import mark_permanent  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    with transaction.atomic():
        log = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if log is None or log.template_key in TEMPLATES.values():
            if (
                log is not None
                and log.status == "sending"
                and claim_token is not None
                and log.claim_token == claim_token
            ):
                mark_permanent(log, "overage_notice_missing")
            return False
        return True


def _notice_hint(email_log_id: str) -> Mapping[str, Any] | None:
    """The notice an email belongs to, read without locks: rechecked once they are held."""
    return (
        DatabaseOverageNotice.objects.filter(email_log_id=UUID(email_log_id))
        .values("pk", "episode_id", "episode__customer_id_snapshot")
        .first()
    )


def overage_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    """The final provider-boundary gate for a notice. An unrelated email passes; no lock is kept during I/O."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.notifications.delivery import mark_permanent  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    hint = _notice_hint(email_log_id)
    if hint is None:
        return _orphan_dispatch_allowed(email_log_id, claim_token)
    with transaction.atomic():
        # The order every notice path takes them in: customer, episode, notice, then the email.
        customer = (
            Customer.all_objects.select_for_update(of=("self",), no_key=True)
            .filter(pk=hint["episode__customer_id_snapshot"])
            .first()
        )
        episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=hint["episode_id"])
        notice = DatabaseOverageNotice.objects.select_for_update().get(pk=hint["pk"])
        log = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if log is None:
            return False
        if claim_token is None or log.claim_token != claim_token or log.status != "sending":
            return False
        if notice.email_log_id != log.pk:
            # The notice was replaced after the queue found it: this email is no longer the one it sends.
            mark_permanent(log, "overage_notice_replaced")
            return False
        if reason := notice_refusal(episode, notice.kind, customer, notice=notice):
            notice.refusal_reason = reason
            notice.save(update_fields=["refusal_reason", "updated_at"])
            mark_permanent(log, reason)
            return False
        return True


def record_notice_acceptance() -> int:
    """Notices whose email the provider accepted. Day 0 accepted late moves the deadline with it."""
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    accepted = 0
    rows = list(
        DatabaseOverageNotice.objects.filter(
            accepted_at__isnull=True,
            email_log__status__in=ACCEPTED_EMAIL_STATES,
            email_log__sent_at__isnull=False,
        ).values_list("pk", "episode_id")
    )
    for pk, episode_id in rows:
        with transaction.atomic():
            # Episode before notice, as every notice path locks them.
            episode = DatabaseOverageEpisode.objects.select_for_update().get(pk=episode_id)
            notice = DatabaseOverageNotice.objects.select_for_update().get(pk=pk)
            if notice.accepted_at is not None or notice.email_log_id is None:
                continue
            sent_at = EmailLog.objects.filter(pk=notice.email_log_id).values_list("sent_at", flat=True).first()
            if sent_at is None:
                continue
            notice.accepted_at = sent_at
            notice.save(update_fields=["accepted_at", "updated_at"])
            if notice.kind == NoticeKind.DAY0:
                deadline = max(episode.deadline_at, notice.accepted_at + grace_period())
                if deadline != episode.deadline_at:
                    episode.deadline_at = deadline
                    episode.save(update_fields=["deadline_at", "updated_at"])
            # Sent means the provider accepted it; a notice refused before the provider never gets here.
            audit_episode(
                episode,
                "database_overage_notice_sent",
                "Database over-allowance notice accepted by the provider",
                kind=notice.kind,
                notice=notice.pk,
                accepted_at=notice.accepted_at.isoformat(),
                **notice.content,
            )
            accepted += 1
    return accepted
