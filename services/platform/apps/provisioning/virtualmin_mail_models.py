"""Explicit hosted-mail enrollment and durable owner intent, separate from node capability."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import timedelta
from typing import Any, ClassVar, cast

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

from .account_hostname_models import AccountHostname
from .virtualmin_models import VirtualminAccount

MAIL_READINESS_MAX_AGE = timedelta(hours=1)
MAIL_OPEN_OPERATION_STATUSES = ("queued", "running", "awaiting_dns", "needs_review")
MAIL_NATIVE_OPERATION_STATUSES = ("running", "needs_review")
_INTENT_FIELDS = (
    "configuration_id",
    "requested_customer_id",
    "requested_by_id",
    "submission_id",
    "intent",
    "target_generation",
    "consent_digest",
    "confirmed_plan",
)


def _binding(account: VirtualminAccount) -> dict[str, Any] | None:
    """Read current ownership; a cached account/server must not validate an old receipt."""
    current = (
        VirtualminAccount.objects.filter(pk=account.pk)
        .values(
            "pk",
            "service_id",
            "service__customer_id",
            "server_id",
            "domain",
            "virtualmin_username",
            "server__hostname",
            "server__ipv4_address",
            "server__ipv6_address",
        )
        .first()
    )
    if current is None:
        return None
    name = (
        AccountHostname.objects.filter(
            account_id=account.pk, target_server_id=current["server_id"], retired_at__isnull=True
        )
        .values("pk", "label", "zone")
        .first()
    )
    if name is None:
        return None
    return {**current, "account_hostname_id": name["pk"], "client_hostname": f"{name['label']}.{name['zone']}"}


def _generation(binding: dict[str, Any]) -> str:
    wire = json.dumps(binding, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(wire.encode()).hexdigest()


def mail_generation(account: VirtualminAccount) -> str:
    """Empty means a live, assigned stable client name cannot currently be proven."""
    binding = _binding(account)
    return _generation(binding) if binding else ""


class MailConfigurationQuerySet(models.QuerySet["VirtualminMailConfiguration"]):
    def update(self, **kwargs: Any) -> int:
        if "mode" in kwargs:
            raise ValidationError(_("Mail mode changes require a verified enrollment transition."))
        if {"account", "account_id"} & set(kwargs):
            raise ValidationError(_("A mail enrollment cannot be assigned to another account."))
        return super().update(**kwargs)


class VirtualminMailConfiguration(ConcurrentTransitionMixin, models.Model):
    class Mode(models.TextChoices):
        EXTERNAL = "external", _("External mail")
        HOSTED = "hosted", _("Hosted mail")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.OneToOneField(VirtualminAccount, on_delete=models.CASCADE, related_name="mail_configuration")
    mode = FSMField(max_length=16, choices=Mode.choices, default=Mode.EXTERNAL, protected=True)
    consent_digest = models.CharField(max_length=64, blank=True)
    proposal = models.JSONField(default=dict, blank=True)
    readiness = models.JSONField(default=dict, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    hosted_since = models.DateTimeField(null=True, blank=True)
    enrollment_id = models.UUIDField(null=True, blank=True, editable=False)
    retirement = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MailConfigurationQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_virtualmin_mail_configuration"
        db_table_comment = "Explicit per-account hosted-mail mode; missing enrollment means external mail."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(mode__in=("external", "hosted")), name="mail_valid_mode"),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        original = type(self).objects.filter(pk=self.pk).values("account_id", "mode").first()
        if original is not None:
            if original["account_id"] != self.account_id:
                raise ValidationError(_("A mail enrollment cannot be assigned to another account."))
            fields = kwargs.get("update_fields")
            if original["mode"] != self.mode and fields is not None:
                if "mode" not in fields:
                    raise ValidationError(_("Save the mail mode transition together with its enrollment state."))
                kwargs["update_fields"] = set(fields) | {
                    "hosted_since",
                    "enrollment_id",
                    "retirement",
                    "readiness",
                    "verified_at",
                    "consent_digest",
                }
        super().save(*args, **kwargs)

    def has_current_readiness(self) -> bool:
        now = timezone.now()
        if (
            self.verified_at is None
            or timezone.is_naive(self.verified_at)
            or not now - MAIL_READINESS_MAX_AGE <= self.verified_at <= now
            or re.fullmatch(r"[a-f0-9]{64}", self.consent_digest) is None
            or not isinstance(self.readiness, dict)
        ):
            return False
        binding = _binding(self.account)
        if binding is None:
            return False
        return bool(
            self.readiness.get("version") == 1
            and self.readiness.get("consent_digest") == self.consent_digest
            and self.readiness.get("generation") == _generation(binding)
            and self.readiness.get("native_ready") is True
            and self.readiness.get("dns_ready") is True
            and isinstance(self.readiness.get("domain_id"), str)
            and self.readiness["domain_id"].isdigit()
            and self.readiness.get("owner") == binding["virtualmin_username"]
            and self.readiness.get("client_hostname") == binding["client_hostname"]
        )

    @transition(
        field=mode,
        source=Mode.EXTERNAL,
        target=Mode.HOSTED,
        conditions=[lambda config: cast("VirtualminMailConfiguration", config).has_current_readiness()],
    )
    def enable_hosted(self) -> None:
        """Only verified native TLS/identity and current DNS permit hosted enrollment."""
        self.hosted_since = timezone.now()
        self.enrollment_id = uuid.uuid4()
        self.retirement = {}

    def can_retire(self) -> bool:
        if not isinstance(self.retirement, dict):
            return False
        try:
            checked = self.retirement.get("checked_at")
            when = parse_datetime(checked) if isinstance(checked, str) else None
        except ValueError:
            return False
        now = timezone.now()
        generation = mail_generation(self.account)
        return bool(
            generation
            and self.enrollment_id is not None
            and self.retirement.get("enrollment_id") == str(self.enrollment_id)
            and when is not None
            and timezone.is_aware(when)
            and now - MAIL_READINESS_MAX_AGE <= when <= now
            and self.hosted_since is not None
            and when >= self.hosted_since
            and self.retirement.get("generation") == generation
            and self.retirement.get("native_disabled") is True
            and self.retirement.get("accepted_queue_empty") is True
        )

    @transition(
        field=mode,
        source=Mode.HOSTED,
        target=Mode.EXTERNAL,
        conditions=[lambda config: cast("VirtualminMailConfiguration", config).can_retire()],
    )
    def disable_hosted(self) -> None:
        """Native teardown and accepted-mail evidence precede the external-mode receipt."""
        self.readiness = {}
        self.verified_at = None
        self.consent_digest = ""

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        saved = self.__dict__.pop("mode", None) if fields is None or "mode" in fields else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved is not None:
                self.__dict__["mode"] = saved
            raise


class MailOperationQuerySet(models.QuerySet["VirtualminMailOperation"]):
    def update(self, **kwargs: Any) -> int:
        if set(kwargs) & {*_INTENT_FIELDS, "configuration", "requested_customer", "requested_by"}:
            raise ValidationError(_("Confirmed mail intent cannot be replaced."))
        return super().update(**kwargs)


class VirtualminMailOperation(models.Model):
    class Intent(models.TextChoices):
        ENABLE = "enable", _("Enable hosted mail")
        DISABLE = "disable", _("Return to external mail")

    class Status(models.TextChoices):
        QUEUED = "queued", _("Queued")
        RUNNING = "running", _("Running")
        AWAITING_DNS = "awaiting_dns", _("Awaiting DNS")
        NEEDS_REVIEW = "needs_review", _("Operator review required")
        COMPLETED = "completed", _("Completed")
        FAILED = "failed", _("Failed")
        CANCELLED = "cancelled", _("Cancelled")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    configuration = models.ForeignKey(VirtualminMailConfiguration, on_delete=models.CASCADE, related_name="operations")
    requested_customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT)
    requested_by = models.ForeignKey("users.User", on_delete=models.PROTECT)
    submission_id = models.UUIDField(editable=False)
    intent = models.CharField(max_length=16, choices=Intent.choices, editable=False)
    target_generation = models.CharField(max_length=64, editable=False)
    consent_digest = models.CharField(max_length=64, editable=False)
    confirmed_plan = models.JSONField(default=dict, editable=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED, db_index=True)
    checkpoint = models.CharField(max_length=48, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=64, blank=True)
    lease_token = models.UUIDField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    resume_after = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MailOperationQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_virtualmin_mail_operations"
        db_table_comment = "Immutable owner consent and fenced native/DNS progress for hosted mail."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["configuration"],
                condition=models.Q(status__in=MAIL_OPEN_OPERATION_STATUSES),
                name="mail_one_open_operation",
            ),
            models.UniqueConstraint(
                fields=["requested_customer", "requested_by", "submission_id"], name="mail_owner_submission_unique"
            ),
            models.CheckConstraint(condition=models.Q(intent__in=("enable", "disable")), name="mail_valid_intent"),
            models.CheckConstraint(
                condition=models.Q(status__in=(*MAIL_OPEN_OPERATION_STATUSES, "completed", "failed", "cancelled")),
                name="mail_operation_valid_status",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        original = type(self).objects.filter(pk=self.pk).values(*_INTENT_FIELDS).first()
        if original is not None and any(original[field] != getattr(self, field) for field in _INTENT_FIELDS):
            raise ValidationError(_("Confirmed mail intent cannot be replaced."))
        super().save(*args, **kwargs)
