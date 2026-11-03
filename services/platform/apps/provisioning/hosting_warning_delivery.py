"""Durable, recipient-bound warning bodies and final provider-boundary policy."""

from __future__ import annotations

from datetime import datetime, timedelta
from html import unescape
from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.html import strip_tags

from apps.common.row_locks import lock_many_and_load

from .hosting_warning_models import (
    HostingWarningDelivery,
    HostingWarningDeliveryPart,
    HostingWarningIntent,
    HostingWarningState,
)
from .hosting_warning_observation import fingerprint, recipient_hash
from .hosting_warning_policy import WarningLevel
from .hosting_warning_privacy import TRANSIENT_REFUSALS, WarningAudience, intent_refusal, load_warning_audience
from .hosting_warning_selectors import warning_resource_data
from .hosting_warning_state import scope_from_snapshot

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.notifications.models import EmailLog, EmailTemplate

    from .virtualmin_models import VirtualminServer

HANDOVER_CAPABILITY_VERSION = "quota-warnings-v1"
TEMPLATE_KEY = "hosting_usage_warning"
SCHEDULE_NAME = "hosting-warning-deliveries"
SWEEP_FUNCTION = "apps.provisioning.hosting_warning_delivery.sweep_hosting_warnings"
MAX_DELIVERY_PARTS = 100
ACCEPTED_EMAIL_STATES = frozenset({"sent", "delivered", "opened", "clicked", "bounced", "complained", "unsubscribed"})


def warnings_enabled() -> bool:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_setting("provisioning.quota_warnings_enabled", False) is True


def notification_handover_refusal(server: VirtualminServer | None) -> str | None:
    """Readiness is installed schema, templates, queue/sweep and transport configuration."""
    from .virtualmin_usage_service import enabled  # noqa: PLC0415

    if not warnings_enabled() or not enabled():
        return "Enable the Platform warning pipeline and canonical usage collection before notification handover."
    if server is not None and server.status != "active":
        return "Activate and verify this node before handing over customer notifications."
    if (
        not getattr(settings, "Q_CLUSTER", None)
        or not getattr(settings, "EMAIL_BACKEND", "")
        or settings.EMAIL_BACKEND.endswith(
            ("dummy.EmailBackend", "console.EmailBackend", "locmem.EmailBackend", "filebased.EmailBackend")
        )
    ):
        return "Configure the durable warning queue and an actual delivery transport before notification handover."
    return _schema_handover_refusal()


def _schema_handover_refusal() -> str | None:
    from django_q.models import Schedule  # noqa: PLC0415

    from apps.notifications.models import EmailPreference, EmailTemplate  # noqa: PLC0415

    try:
        tables = set(connection.introspection.table_names())
        if not {
            model._meta.db_table
            for model in (HostingWarningState, HostingWarningIntent, HostingWarningDelivery, HostingWarningDeliveryPart)
        }.issubset(tables):
            return "Apply the durable warning schema before notification handover."
        EmailPreference.objects.values_list("quota_warnings", flat=True).first()
        templates = list(
            EmailTemplate.objects.filter(
                key=TEMPLATE_KEY, locale__in=("en", "ro"), category="quota_warnings", is_active=True
            )
        )
        if {template.locale for template in templates} != {"en", "ro"} or not _templates_keep_entries(templates):
            return "Install active English and Romanian hosting warning templates before notification handover."
        if not Schedule.objects.filter(
            Q(repeats=-1) | Q(repeats__gt=0),
            name=SCHEDULE_NAME,
            func=SWEEP_FUNCTION,
            schedule_type="I",
            minutes__range=(1, 5),
        ).exists():
            return "Register the durable hosting warning sweep before notification handover."
    except DatabaseError:
        return "Apply the warning and preference migrations before notification handover."
    return None


def _templates_keep_entries(templates: list[EmailTemplate]) -> bool:
    from apps.notifications.services import (  # noqa: PLC0415 -- Same real rendering contract as delivery.
        render_template_safely,
    )

    entries = ["a" * 700, "b" * 700]
    try:
        for template in templates:
            for critical in (True, False):
                for body in (template.body_text, template.body_html):
                    if not body:
                        continue
                    rendered = render_template_safely(
                        body,
                        {
                            "warning_entries": entries,
                            "warning_lines": "\n".join(entries),
                            "critical_notice": critical,
                        },
                        autoescape=False,
                    )
                    if not all(entry in rendered for entry in entries):
                        return False
    except ValidationError:
        return False
    return True


def setup_warning_pipeline() -> dict[str, str]:
    """Install defaults idempotently; existing operator template content is preserved."""
    from django_q.models import Schedule  # noqa: PLC0415

    from apps.notifications.models import EmailTemplate  # noqa: PLC0415

    for locale, subject, lead, help_text in (
        (
            "en",
            "Hosting allowance warning",
            "Your hosting usage has reached an included allowance.",
            "Review your usage or choose a suitable hosting plan.",
        ),
        (
            "ro",
            "Avertizare privind limita găzduirii",
            "Utilizarea găzduirii a atins o limită inclusă.",
            "Verificați utilizarea sau alegeți un abonament de găzduire potrivit.",
        ),
    ):
        EmailTemplate.objects.get_or_create(
            key=TEMPLATE_KEY,
            locale=locale,
            defaults={
                "category": "quota_warnings",
                "subject": subject,
                "body_text": lead
                + "\n{% for entry in warning_entries %}{{ entry }}\n{% endfor %}"
                + help_text
                + "\n{% if not critical_notice %}{{ unsubscribe_url }}{% endif %}",
                "body_html": "<p>"
                + lead
                + "</p><ul>{% for entry in warning_entries %}<li>{{ entry }}</li>{% endfor %}</ul><p>"
                + help_text
                + "</p>{% if not critical_notice %}<p>{{ unsubscribe_url }}</p>{% endif %}",
            },
        )
    _schedule, created = Schedule.objects.update_or_create(
        name=SCHEDULE_NAME,
        defaults={
            "func": SWEEP_FUNCTION,
            "schedule_type": "I",
            "minutes": 5,
            "repeats": -1,
        },
    )
    return {"hosting_warnings": "created" if created else "updated"}


def enqueue_warning_sweep() -> None:
    from django_q.tasks import async_task  # noqa: PLC0415

    async_task(SWEEP_FUNCTION, task_name="hosting-warning-deliveries")


def _body_hash(log: EmailLog) -> str:
    return fingerprint(
        {
            "subject": log.subject,
            "text": log.get_decrypted_body_text(),
            "html": log.get_decrypted_body_html(),
            "recipient": log.to_addr.strip().casefold(),
        }
    )


def _cancel(intent: HostingWarningIntent, reason: str) -> None:
    if intent.phase in {"pending", "linked"}:
        intent.cancel(reason)
        intent.save(update_fields=["phase", "refusal_reason", "updated_at"])


def _locked_intents(ids: list[UUID]) -> list[HostingWarningIntent]:
    return lock_many_and_load(
        HostingWarningIntent.objects.select_related("state").filter(pk__in=ids).order_by("pk"), no_key=True
    )


def _warning_line(name: str, intent: HostingWarningIntent, current: dict[str, object], locale: str) -> str:
    allowance, observed, used = current["operational_allowance_mib"], current["observed_at"], current["used_bytes"]
    if locale == "ro":
        label = "spațiu pe disc" if intent.resource == "disk" else "trafic lunar"
        line = f"{name[:96]}: {label} a atins cel puțin {intent.threshold}% din limita inclusă ({allowance} MiB); {used} octeți măsurați la {observed}."
        partial = " Acoperirea traficului este parțială; valoarea măsurată este o limită inferioară."
    else:
        line = f"{name[:96]}: {intent.resource} has reached at least {intent.threshold}% of the included allowance ({allowance} MiB); {used} bytes measured at {observed}."
        partial = " Bandwidth coverage is partial; measured bytes are a lower bound."
    return line + (partial if current["availability"] == "partial" else "")


def _raise_line(data: dict[str, object] | None, locale: str) -> str:
    if not data:
        return ""
    if locale == "ro":
        descriptions = {
            "requested": "Suplimentul temporar de spațiu pe disc este solicitat; capacitatea suplimentară nu este încă verificată.",
            "verified": "Suplimentul temporar de spațiu pe disc este verificat până la expirare.",
            "expired_attention": "Suplimentul temporar de spațiu pe disc a expirat; revenirea la limita de bază necesită verificare.",
            "expired": "Suplimentul temporar de spațiu pe disc a expirat.",
        }
        return f"{descriptions[str(data['state'])]} Expirare: {data['expires_at']}. Avertizările rămân raportate la limita inclusă în abonament."
    descriptions = {
        "requested": "A temporary disk raise is requested; additional capacity is not yet verified.",
        "verified": "A temporary disk raise is verified until its expiry.",
        "expired_attention": "The temporary disk raise expired; base-cap restoration is awaiting verification.",
        "expired": "The temporary disk raise expired.",
    }
    return f"{descriptions[str(data['state'])]} Expiry: {data['expires_at']}. Warnings remain based on the purchased allowance."


def _link_customer(customer_id: int, at: datetime) -> int:
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.customers.services import get_customer_locale  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415
    from apps.notifications.services import EmailService, validate_template_context  # noqa: PLC0415

    with transaction.atomic():
        customer = Customer.all_objects.select_for_update(of=("self",), no_key=True).filter(pk=customer_id).first()
        if customer is None:
            return 0
        ids = list(
            HostingWarningIntent.objects.filter(customer_id_snapshot=customer_id, phase="pending", due_at__lte=at)
            .exclude(delivery_parts__active=True)
            .order_by("-threshold", "due_at", "pk")
            .values_list("pk", flat=True)
        )
        intents = _locked_intents(ids)
        audience = load_warning_audience(intents, at=at)
        locale = get_customer_locale(customer)
        selected: list[HostingWarningIntent] = []
        snapshots: list[dict[str, object]] = []
        lines: list[str] = []
        for intent in intents:
            if len(selected) >= MAX_DELIVERY_PARTS:
                break
            reason = intent_refusal(intent, customer, audience, at)
            if reason:
                if reason not in TRANSIENT_REFUSALS:
                    _cancel(intent, reason)
                continue
            account = audience.accounts[intent.state.account_id]
            service = audience.services[intent.service_id_snapshot]
            current = warning_resource_data(
                service, account.usage_state, intent.state, audience.limits.get(service.pk), at
            )
            selected.append(intent)
            raised = audience.raises.get(service.pk) if intent.resource == "disk" else None
            snapshots.append(
                {
                    "id": str(intent.pk),
                    "identity": intent.identity,
                    "threshold": intent.threshold,
                    "allowance_mib": current["operational_allowance_mib"],
                    "scope": intent.scope_snapshot,
                    "raise": raised,
                }
            )
            lines.append(_warning_line(service.service_name, intent, current, locale))
            if raised:
                lines.append(_raise_line(raised, locale))
        if not selected:
            return 0
        lines = [cast("str", validate_template_context({"line": line})["line"]) for line in lines]
        previous = (
            HostingWarningDelivery.objects.filter(
                parts__intent_id__in=[item.pk for item in selected],
                customer_id_snapshot=customer_id,
                recipient_hash=recipient_hash(customer.primary_email),
                phase="refused",
                certainty="never_dispatched",
            )
            .distinct()
            .order_by("-created_at", "-pk")
            .first()
        )
        delivery = HostingWarningDelivery.objects.create(
            customer_id_snapshot=customer_id,
            recipient_hash=recipient_hash(customer.primary_email),
            parent=previous,
            version=previous.version + 1 if previous else 1,
            intent_snapshot={"version": 1, "parts": snapshots},
        )
        HostingWarningDeliveryPart.objects.bulk_create(
            [HostingWarningDeliveryPart(delivery=delivery, intent=intent) for intent in selected]
        )
        result = EmailService.send_template_email(
            template_key=TEMPLATE_KEY,
            recipient=customer.primary_email,
            context={
                "warning_lines": "\n".join(lines),
                "warning_entries": lines,
                "critical_notice": any(item.threshold == WarningLevel.CRITICAL for item in selected),
            },
            locale=locale,
            customer=customer,
            async_send=True,
            require_async=True,
            essential=any(item.threshold == WarningLevel.CRITICAL for item in selected),
        )
        if not result.success or result.email_log_id is None:
            # Roll back all publication/link facts; the original intents remain due.
            raise ValueError("The durable warning email could not be stored: " + str(result.error))
        log = EmailLog.objects.get(pk=result.email_log_id)
        text = log.get_decrypted_body_text()
        html = log.get_decrypted_body_html()
        if not all(line in text and (not html or line in unescape(strip_tags(html))) for line in lines):
            raise ValueError("The warning template did not preserve every selected warning entry")
        delivery.email_log = log
        delivery.intent_snapshot = {**delivery.intent_snapshot, "body_hash": _body_hash(log)}
        delivery.link()
        delivery.save(update_fields=["email_log", "intent_snapshot", "phase", "updated_at"])
        for intent in selected:
            intent.link()
            intent.save(update_fields=["phase", "updated_at"])
        return 1


def _refuse_delivery(
    delivery: HostingWarningDelivery, log: EmailLog, intents: list[HostingWarningIntent], reason: str
) -> None:
    from apps.notifications.delivery import mark_permanent  # noqa: PLC0415

    mark_permanent(log, reason)
    delivery.refuse(reason)
    delivery.save(update_fields=["phase", "refusal_reason", "refused_at", "certainty", "updated_at"])
    if delivery.certainty == "never_dispatched":
        HostingWarningDeliveryPart.objects.filter(delivery=delivery, active=True).update(active=False)
        for intent in intents:
            if intent.phase == "linked":
                intent.requeue()
                intent.save(update_fields=["phase", "updated_at"])
        transaction.on_commit(enqueue_warning_sweep, robust=True)


def _orphan_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    from apps.notifications.delivery import mark_permanent  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    with transaction.atomic():
        log = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if log is None:
            return False
        if log.template_key != TEMPLATE_KEY:
            return True
        if log.status == "sending" and log.claim_token == claim_token and claim_token is not None:
            mark_permanent(log, "warning_intent_missing")
        return False


def _snapshot_parts(delivery: HostingWarningDelivery) -> dict[str, dict[str, object]] | None:
    raw = delivery.intent_snapshot
    if (
        not isinstance(raw, dict)
        or set(raw) != {"version", "parts", "body_hash"}
        or type(raw["version"]) is not int
        or raw["version"] != 1
    ):
        return None
    if not isinstance(raw["parts"], list) or not raw["parts"]:
        return None
    result: dict[str, dict[str, object]] = {}
    try:
        for part in raw["parts"]:
            if not isinstance(part, dict) or set(part) != {
                "id",
                "identity",
                "threshold",
                "allowance_mib",
                "scope",
                "raise",
            }:
                return None
            key = str(UUID(part["id"]))
            scope_from_snapshot(part["scope"])
            if key in result or type(part["threshold"]) is not int or part["threshold"] not in {80, 95, 100}:
                return None
            result[key] = part
    except (ValueError, TypeError, AttributeError):
        return None
    return result


def _binding_refusal(
    intent: HostingWarningIntent, snapshot: dict[str, object], audience: WarningAudience, at: datetime
) -> str | None:
    if intent.phase != "linked":
        return "warning_intent_obsolete"
    if (
        snapshot.get("identity") != intent.identity
        or snapshot.get("scope") != intent.scope_snapshot
        or snapshot.get("threshold") != intent.threshold
    ):
        return "warning_body_changed"
    service = audience.services.get(intent.service_id_snapshot)
    account = audience.accounts.get(intent.state.account_id)
    if service and account:
        current = warning_resource_data(service, account.usage_state, intent.state, audience.limits.get(service.pk), at)
        if snapshot.get("allowance_mib") != current["operational_allowance_mib"]:
            return "warning_allowance_changed"
        if intent.resource == "disk" and snapshot.get("raise") != audience.raises.get(service.pk):
            return "warning_raise_changed"
    return None


def _delivery_refusal(
    delivery: HostingWarningDelivery,
    log: EmailLog,
    customer: Customer | None,
    intents: list[HostingWarningIntent],
    at: datetime,
) -> str | None:
    if not warnings_enabled():
        return "warning_pipeline_disabled"
    if customer is None or log.customer_id != delivery.customer_id_snapshot:
        return "warning_customer_unavailable"
    if (
        recipient_hash(log.to_addr) != delivery.recipient_hash
        or recipient_hash(customer.primary_email) != delivery.recipient_hash
    ):
        return "warning_recipient_changed"
    snapshots = _snapshot_parts(delivery)
    if snapshots is None or set(snapshots) != {str(intent.pk) for intent in intents}:
        return "warning_intent_missing"
    if log.template_key != TEMPLATE_KEY or _body_hash(log) != delivery.intent_snapshot.get("body_hash"):
        return "warning_body_changed"
    audience = load_warning_audience(intents, at=at)
    return next(
        (
            reason
            for intent in intents
            if (
                reason := intent_refusal(intent, customer, audience, at)
                or _binding_refusal(intent, snapshots[str(intent.pk)], audience, at)
            )
        ),
        None,
    )


def warning_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    """The final provider-boundary gate. No row lock is retained during provider I/O."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.notifications.delivery import mark_permanent  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    hint = (
        HostingWarningDelivery.objects.filter(email_log_id=UUID(email_log_id))
        .values("pk", "customer_id_snapshot")
        .first()
    )
    if hint is None:
        return _orphan_dispatch_allowed(email_log_id, claim_token)
    with transaction.atomic():
        customer = (
            Customer.all_objects.select_for_update(of=("self",), no_key=True)
            .filter(pk=hint["customer_id_snapshot"])
            .first()
        )
        delivery = HostingWarningDelivery.objects.select_for_update(of=("self",)).get(pk=hint["pk"])
        intents = _locked_intents(list(delivery.parts.filter(active=True).values_list("intent_id", flat=True)))
        log = EmailLog.objects.select_for_update().get(pk=email_log_id)
        at = timezone.now()
        if (
            claim_token is None
            or log.claim_token != claim_token
            or log.status != "sending"
            or log.lease_until is None
            or log.lease_until <= at
            or delivery.email_log_id != log.pk
        ):
            return False
        if delivery.phase not in {"linked", "dispatching"}:
            mark_permanent(log, "warning_delivery_obsolete")
            return False
        reason = _delivery_refusal(delivery, log, customer, intents, at)
        if reason:
            _refuse_delivery(delivery, log, intents, reason)
            return False
        delivery.dispatch()
        delivery.save(update_fields=["phase", "first_dispatch_claimed_at", "certainty", "updated_at"])
        return True


def _record_acceptance() -> None:
    with transaction.atomic():
        deliveries = lock_many_and_load(
            HostingWarningDelivery.objects.select_related("email_log")
            .filter(
                phase__in=("linked", "dispatching"),
                email_log__status__in=ACCEPTED_EMAIL_STATES,
            )
            .order_by("pk"),
            no_key=True,
        )
        for delivery in deliveries:
            if (
                delivery.email_log is None
                or delivery.first_dispatch_claimed_at is None
                or delivery.email_log.sent_at is None
            ):
                continue
            delivery.accept(delivery.email_log.sent_at)
            delivery.save(update_fields=["phase", "accepted_at", "certainty", "updated_at"])
            for intent in _locked_intents(list(delivery.parts.filter(active=True).values_list("intent_id", flat=True))):
                if intent.phase in {"pending", "linked"}:
                    intent.delivered()
                    intent.save(update_fields=["phase", "updated_at"])


def _due_reminders(at: datetime) -> None:
    from apps.customers.models import Customer  # noqa: PLC0415

    # The recipient/episode key, not the transport version, owns the single reminder.
    candidates = list(
        HostingWarningDeliveryPart.objects.filter(
            active=True,
            delivery__phase="accepted",
            delivery__accepted_at__lte=at - timedelta(hours=48),
            intent__threshold=100,
        )
        .exclude(intent__kind="reminder")
        .values("intent_id", "delivery__accepted_at")
    )
    for candidate in candidates:
        accepted_at = candidate["delivery__accepted_at"]
        if accepted_at is None:
            continue
        hint = HostingWarningIntent.objects.values("customer_id_snapshot").get(pk=candidate["intent_id"])
        with transaction.atomic():
            customer = (
                Customer.all_objects.select_for_update(of=("self",), no_key=True)
                .filter(pk=hint["customer_id_snapshot"])
                .first()
            )
            intents = _locked_intents([candidate["intent_id"]])
            if customer is None or not intents:
                continue
            original = intents[0]
            if intent_refusal(original, customer, load_warning_audience(intents, at=at), at):
                continue
            key = {"parent": str(original.pk), "kind": "reminder", "recipient": original.recipient_hash}
            HostingWarningIntent.objects.get_or_create(
                identity=fingerprint(key),
                defaults={
                    "state": original.state,
                    "service_id_snapshot": original.service_id_snapshot,
                    "customer_id_snapshot": original.customer_id_snapshot,
                    "owner_scope": original.owner_scope,
                    "resource": original.resource,
                    "generation": original.generation,
                    "threshold": 100,
                    "recipient_hash": original.recipient_hash,
                    "kind": "reminder",
                    "due_at": accepted_at + timedelta(hours=48),
                    "reading": original.reading,
                    "scope_snapshot": original.scope_snapshot,
                    "evidence_snapshot": original.evidence_snapshot,
                    "parent": original,
                },
            )


def sweep_hosting_warnings(at: datetime | None = None) -> dict[str, int]:
    instant = at or timezone.now()
    _record_acceptance()
    if not warnings_enabled():
        return {"linked": 0}
    _due_reminders(instant)
    customers = list(
        HostingWarningIntent.objects.filter(phase="pending", due_at__lte=instant)
        .values_list("customer_id_snapshot", flat=True)
        .distinct()
        .order_by("customer_id_snapshot")
    )
    linked = 0
    for customer_id in customers:
        linked += _link_customer(customer_id, instant)
    return {"linked": linked}
