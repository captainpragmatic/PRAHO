"""Account hostnames: the opaque provider name that follows a hosting account across nodes (ADR-0061).

A name is `<label>.<zone>`. The label is eight lowercase letters or digits, assigned once and never reused:
the row outlives its account (`SET_NULL`), so a retired label stays taken. On a node the name is a
Virtualmin sub-server of the customer's domain (lab contract `docs/domain/virtualmin-account-subserver-contract.md`).
"""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

LABEL_PATTERN = r"^[a-z0-9]{8}$"


class AccountHostname(models.Model):
    """One account's provider hostname and the DNS records PRAHO publishes for it.

    `target_server` is where DNS must point. Only provisioning success, cutover and recovery change it;
    the reconcile sweep converges DNS to it, never to `account.server`.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    label = models.CharField(
        max_length=8, unique=True, validators=[RegexValidator(LABEL_PATTERN)], verbose_name=_("Label")
    )
    account = models.OneToOneField(
        "provisioning.VirtualminAccount",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="account_hostname",
    )
    # PROTECT: a node that live names point at cannot vanish under them.
    target_server = models.ForeignKey(
        "provisioning.VirtualminServer",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="account_hostnames",
    )
    zone = models.CharField(max_length=253, verbose_name=_("Zone"))
    # Per record type: intended content, applied content, provider record id, applied TTL.
    records = models.JSONField(default=dict, blank=True)
    previous_ttl = models.PositiveIntegerField(null=True, blank=True)
    ttl_lowered_at = models.DateTimeField(null=True, blank=True)
    last_reconciled_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_account_hostnames"
        verbose_name = _("Account Hostname")
        verbose_name_plural = _("Account Hostnames")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=Q(label__regex=LABEL_PATTERN), name="account_hostname_label_shape"),
        ]

    def __str__(self) -> str:
        return self.fqdn

    @property
    def fqdn(self) -> str:
        return f"{self.label}.{self.zone}"


class AccountNameCertificate(models.Model):
    """The account name's certificate: the material in force, and the current issuance attempt.

    The two are kept apart so a renewal that is ordering or failed never takes a valid certificate out of
    service. Readiness is valid material, not the attempt state (`has_valid_material`). Only vault
    references are stored here, never PEM.
    """

    class AttemptStatus(models.TextChoices):
        PENDING = "pending", _("Pending")
        ORDERING = "ordering", _("Ordering")
        ISSUED = "issued", _("Issued")
        FAILED = "failed", _("Failed")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.OneToOneField(AccountHostname, on_delete=models.CASCADE, related_name="certificate")

    # The material in force.
    current_certificate_ref = models.CharField(max_length=255, blank=True)
    current_key_ref = models.CharField(max_length=255, blank=True)
    current_not_after = models.DateTimeField(null=True, blank=True)

    # The issuance attempt (first issuance or renewal).
    attempt_status = models.CharField(max_length=10, choices=AttemptStatus.choices, default=AttemptStatus.PENDING)
    attempt_is_renewal = models.BooleanField(default=False)
    attempt_order_url = models.CharField(max_length=500, blank=True)
    attempt_reserved_at = models.DateTimeField(null=True, blank=True)
    retry_after = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_account_name_certificates"
        verbose_name = _("Account Name Certificate")
        verbose_name_plural = _("Account Name Certificates")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(attempt_status__in=["pending", "ordering", "issued", "failed"]),
                name="account_name_certificate_attempt_status",
            ),
        ]

    def __str__(self) -> str:
        return f"certificate for {self.hostname_id}"

    def has_valid_material(self) -> bool:
        """Whether a certificate for the name is in force, whatever the current attempt is doing."""
        return bool(
            self.current_certificate_ref
            and self.current_key_ref
            and self.current_not_after is not None
            and self.current_not_after > timezone.now()
        )


class AccountNameCertificateBudget(models.Model):
    """The lock row for one zone's new-certificate budget.

    Reservations take this row with `select_for_update`; the rolling count is computed from
    `AccountNameCertificate.attempt_reserved_at` for non-renewal attempts in the zone.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    zone = models.CharField(max_length=253, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_account_name_certificate_budgets"
        verbose_name = _("Account Name Certificate Budget")
        verbose_name_plural = _("Account Name Certificate Budgets")

    def __str__(self) -> str:
        return f"certificate budget for {self.zone}"
