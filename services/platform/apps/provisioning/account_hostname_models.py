"""Account hostnames: the opaque provider name that follows a hosting account across nodes (ADR-0061).

A name is `<label>.<zone>`. The label is eight lowercase letters or digits, assigned once and never reused:
the row outlives its account (`SET_NULL`) and refuses deletion, so a retired label stays taken. On a node the name is a
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


class ProtectedLabelError(Exception):
    """An account hostname row cannot be deleted: deleting it would free its label for reuse."""


_LABEL_IMMUTABLE = "An account hostname's label never changes; a label is never reused."


class AccountHostnameQuerySet(models.QuerySet["AccountHostname"]):
    def delete(self) -> tuple[int, dict[str, int]]:
        raise ProtectedLabelError("Account hostnames are retired, never deleted; a label is never reused.")

    def update(self, **kwargs: object) -> int:
        if "label" in kwargs:
            raise ProtectedLabelError(_LABEL_IMMUTABLE)
        return super().update(**kwargs)

    def bulk_update(self, objs: object, fields: object, *args: object, **kwargs: object) -> int:
        if "label" in list(fields):  # type: ignore[call-overload]  # fields is any iterable of names
            raise ProtectedLabelError(_LABEL_IMMUTABLE)
        return super().bulk_update(objs, fields, *args, **kwargs)  # type: ignore[arg-type]  # forwarded unchanged


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
    # The sweep's rotation: set on every pass whatever the outcome, so names that cannot be published
    # yet never hold the head of the queue (`last_reconciled_at` keeps gating the one-time node step).
    last_swept_at = models.DateTimeField(null=True, blank=True)
    # One node step (create, link, install) at a time per name, whichever task runs it.
    node_lease_token = models.CharField(max_length=32, blank=True)
    node_lease_until = models.DateTimeField(null=True, blank=True)
    # Set once, when the customer is told the name is live (P1.12).
    activation_notified_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AccountHostnameQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_account_hostnames"
        verbose_name = _("Account Hostname")
        verbose_name_plural = _("Account Hostnames")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=Q(label__regex=LABEL_PATTERN), name="account_hostname_label_shape"),
        ]

    def __str__(self) -> str:
        return self.fqdn

    def save(self, *args: object, **kwargs: object) -> None:
        if not self._state.adding:
            stored = type(self).objects.filter(pk=self.pk).values_list("label", flat=True).first()
            if stored is not None and stored != self.label:
                raise ProtectedLabelError(_LABEL_IMMUTABLE)
        super().save(*args, **kwargs)  # type: ignore[arg-type]  # forwarded unchanged

    def delete(self, *args: object, **kwargs: object) -> tuple[int, dict[str, int]]:
        raise ProtectedLabelError("Account hostnames are retired, never deleted; a label is never reused.")

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
    # When this name took a new-certificate budget slot; a renewal never touches it.
    attempt_reserved_at = models.DateTimeField(null=True, blank=True)
    # One attempt's identity (its vault ids), kept across a resume or a takeover; its age.
    attempt_id = models.CharField(max_length=32, blank=True)
    attempt_started_at = models.DateTimeField(null=True, blank=True)
    # The worker holding the attempt: every write of the attempt is conditioned on this token.
    attempt_token = models.CharField(max_length=32, blank=True)
    attempt_lease_until = models.DateTimeField(null=True, blank=True)
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


class AccountNameCertificateInstall(models.Model):
    """A certificate for an account name that is installed on a node.

    Written when an install succeeds (`account_name_certificates.record_installation`), one row per
    (name, node). A name is ready for a node when the row for that node holds an unexpired certificate:
    the installed material, not the issuance attempt, is what the node serves.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.ForeignKey(AccountHostname, on_delete=models.CASCADE, related_name="certificate_installs")
    server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.CASCADE, related_name="account_name_certificate_installs"
    )
    # The vault reference of the certificate that was installed, so a newer one is known to be missing.
    certificate_ref = models.CharField(max_length=255)
    not_after = models.DateTimeField()
    installed_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_account_name_certificate_installs"
        verbose_name = _("Account Name Certificate Install")
        verbose_name_plural = _("Account Name Certificate Installs")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["hostname", "server"], name="account_name_certificate_install_per_node"),
        ]

    def __str__(self) -> str:
        return f"certificate for {self.hostname_id} on {self.server_id}"
