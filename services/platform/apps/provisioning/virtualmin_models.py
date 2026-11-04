"""
Virtualmin Integration Models - PRAHO Platform
Models for Virtualmin server management and account tracking.
"""

from __future__ import annotations

import contextlib
import logging
import re
import uuid
from collections.abc import Collection, Iterable
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, ClassVar

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.model_secrets import (
    NaturalKeyQuerySet,
    NaturalKeySecretsMixin,
    decrypt_model_secret,
    encrypt_model_secret,
)
from apps.common.types import Retriability
from apps.provisioning.virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE

from .hosted_zone_ownership import AccountOwnershipQuerySet, remember_ownership, save_with_ownership

logger = logging.getLogger(__name__)

# Health check constants. The sweep runs every 10 minutes; freshness covers
# 2.5 cadences so a single missed sweep never blanks placement fleet-wide.
HEALTH_CHECK_FRESH_SECONDS = 1500  # 25 minutes
# Consecutive failed checks (~1h at 10-min cadence) before a server is
# auto-failed; only auto-failed servers are auto-recovered.
HEALTH_AUTO_FAIL_THRESHOLD = 6
_EXECUTION_RECOVERY_MARGIN_SECONDS = 60

# Operations whose interruption or unknown outcome parks the job in attention (keeping the
# account's operation exclusion) instead of failing it into the retry pool: the command may
# already have destroyed the domain, so a blind replay or a released exclusion is unsafe.
UNCERTAIN_WHEN_INTERRUPTED_OPERATIONS = ("delete_domain",)

# Keys a persisted job result never keeps. Job results hold Virtualmin
# response envelopes, and 8.x listing rows carry `hashed_password` and
# `password_for_mysql`; the create-domain parameters carry `pass`.
_SECRET_KEY_RE = re.compile(
    r"((^|[-_])pass$|passw|passphrase|secret|token|hashed|private_key|api_key|access_key)", re.I
)


def without_secrets(value: Any) -> Any:
    """A copy of a JSON-like value with every secret-looking key removed, at any depth."""
    if isinstance(value, dict):
        return {key: without_secrets(item) for key, item in value.items() if not _SECRET_KEY_RE.search(str(key))}
    if isinstance(value, list):
        return [without_secrets(item) for item in value]
    return value


class VirtualminServer(NaturalKeySecretsMixin, models.Model):
    """
    Virtualmin server instance for hosting services.

    Each server runs Virtualmin and can host multiple virtual domains.
    PRAHO manages multiple servers for load distribution and redundancy.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("active", _("Active")),
        ("maintenance", _("Maintenance")),
        ("disabled", _("Disabled")),
        ("failed", _("Failed")),
    )

    # The API password is bound to the hostname it authenticates to: a hostname changed in the database
    # leaves it unreadable instead of sending it to another host (#751 follow-up, M19).
    SECRET_NATURAL_KEY: ClassVar[tuple[str, ...]] = ("hostname",)
    BOUND_SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("encrypted_api_password",)

    # Server identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True, verbose_name=_("Server Name"))
    hostname = models.CharField(max_length=255, unique=True, verbose_name=_("Hostname"))
    # Where account hostnames point (ADR-0061): the A and AAAA record contents.
    ipv4_address = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True, verbose_name=_("IPv4 Address"))
    ipv6_address = models.GenericIPAddressField(protocol="IPv6", null=True, blank=True, verbose_name=_("IPv6 Address"))

    # API configuration
    api_port = models.PositiveIntegerField(default=10000, verbose_name=_("API Port"))
    ssh_port = models.PositiveIntegerField(
        default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)], verbose_name=_("SSH Port")
    )
    api_path = models.CharField(max_length=100, default="/virtual-server/remote.cgi", verbose_name=_("API Path"))
    use_ssl = models.BooleanField(default=True, verbose_name=_("Use SSL"))
    ssl_verify = models.BooleanField(default=True, verbose_name=_("Verify SSL Certificate"))
    ssl_cert_fingerprint = models.CharField(max_length=128, blank=True, verbose_name=_("SSL Certificate Fingerprint"))

    api_username = models.CharField(max_length=100, verbose_name=_("API Username"))
    encrypted_api_password = models.BinaryField(verbose_name=_("Encrypted API Password"))

    # Server capacity and limits
    max_domains = models.PositiveIntegerField(
        default=1000, validators=[MinValueValidator(1)], verbose_name=_("Maximum Domains")
    )
    max_disk_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Maximum Disk Space (GB)"))
    max_bandwidth_gb = models.PositiveIntegerField(
        null=True, blank=True, verbose_name=_("Maximum Bandwidth (GB/month)")
    )

    # Server status and health
    is_draining = models.BooleanField(default=False)
    security_policy_version = models.CharField(max_length=40, default="virtualmin-web-only-v2", editable=False)
    security_configuration_digest = models.CharField(max_length=64, default="", blank=True, editable=False)
    security_state = models.CharField(
        max_length=32,
        choices=[
            ("unreviewed", _("Unreviewed")),
            ("acknowledged_source_only", _("Acknowledged migration source")),
            ("verified_web", _("Verified web-only")),
        ],
        default="unreviewed",
        editable=False,
    )
    current_security_review = models.ForeignKey(
        "provisioning.NodeSecurityReview",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        editable=False,
    )
    security_operation = models.UUIDField(null=True, blank=True, editable=False)
    legacy_security_admission = models.BooleanField(default=False, editable=False)
    verified_security_review = models.ForeignKey(
        "provisioning.NodeSecurityReview",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        editable=False,
    )
    imported_ssh_host_keys = models.TextField(blank=True, default="", editable=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active", verbose_name=_("Status"))
    last_health_check = models.DateTimeField(null=True, blank=True)
    health_check_error = models.TextField(blank=True)
    # Consecutive failed health checks; only a sustained streak may auto-fail
    # the server, and only auto-failed servers are ever auto-recovered.
    consecutive_health_failures = models.PositiveIntegerField(default=0)
    failed_by_health_check = models.BooleanField(default=False)

    # Load balancing and placement
    weight = models.PositiveIntegerField(
        default=100, help_text=_("Server placement weight (higher = strictly preferred; ties broken by current load)")
    )
    region = models.CharField(max_length=50, blank=True, help_text=_("Geographic region for placement decisions"))
    tags = models.JSONField(default=list, help_text=_("Server tags for placement policies"))

    # Statistics and monitoring
    current_domains = models.PositiveIntegerField(default=0)
    current_disk_usage_gb = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    current_bandwidth_usage_gb = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager.from_queryset(NaturalKeyQuerySet)()

    class Meta:
        db_table = "provisioning_virtualmin_servers"
        verbose_name = _("Virtualmin Server")
        verbose_name_plural = _("Virtualmin Servers")
        ordering: ClassVar[tuple[str, ...]] = ("name",)

    def __str__(self) -> str:
        return f"{self.name} ({self.hostname})"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Accept legacy kwargs for backward compatibility with tests."""
        # Only apply transformations when creating new instances, not loading from database
        # Database loading will have args but no meaningful kwargs for field mapping
        if kwargs and not (args and len(args) > 1):
            # Handle legacy field names from old test files
            if "capacity" in kwargs:
                kwargs["max_domains"] = kwargs.pop("capacity")

            # Handle legacy status values
            if "status" in kwargs:
                status_mapping = {
                    "healthy": "active",
                    "active": "active",  # Keep as-is
                    "maintenance": "maintenance",  # Keep as-is
                    "offline": "disabled",
                    "failed": "failed",  # Keep as-is
                }
                status = kwargs["status"]
                if status in status_mapping:
                    kwargs["status"] = status_mapping[status]

            # Set default required fields if not provided (for testing)
            if "name" not in kwargs and "hostname" in kwargs:
                # Generate name from hostname for tests
                kwargs["name"] = kwargs["hostname"].replace(".", "-")

            if "api_username" not in kwargs:
                kwargs["api_username"] = "test_user"

        super().__init__(*args, **kwargs)

    @property
    def effective_ssh_port(self) -> int:
        """A managed deployment owns its live port; manual servers use their own."""
        try:
            return int(self.node_deployment.ssh_port)
        except ObjectDoesNotExist:
            return int(self.ssh_port)

    @property
    def enrolled_ssh_host_keys(self) -> str | None:
        """Public host keys shared with provisioning, or configured manual trust."""
        from apps.infrastructure.ssh_transport import (  # noqa: PLC0415 -- Avoid model import cycle.
            resolve_node_host_keys,
        )

        try:
            deployment = self.node_deployment
        except ObjectDoesNotExist:
            return self.imported_ssh_host_keys or None
        return resolve_node_host_keys(deployment)

    @property
    def api_url(self) -> str:
        """Get full API URL for this server"""
        protocol = "https" if self.use_ssl else "http"
        return f"{protocol}://{self.hostname}:{self.api_port}{self.api_path}"

    @property
    def capacity_percentage(self) -> float:
        """Get current capacity usage percentage"""
        if self.max_domains == 0:
            return 0.0
        return (self.current_domains / self.max_domains) * 100

    @property
    def is_healthy(self) -> bool:
        """Check if server is healthy: active, recently verified, no live error.

        last_health_check is stamped on SUCCESS only — a just-failed server
        must never look healthy merely because it was probed recently.
        """
        if self.status != "active":
            return False
        if self.health_check_error:
            return False

        if self.last_health_check:
            age = timezone.now() - self.last_health_check
            return age.total_seconds() < HEALTH_CHECK_FRESH_SECONDS

        return False

    def get_api_password(self) -> str:
        """Decrypt and return API password.

        Raises DecryptionError on key rotation / corrupted ciphertext
        so callers can handle it explicitly instead of silently getting "".
        """
        return decrypt_model_secret(self, "encrypted_api_password", bytes(self.encrypted_api_password).decode())

    def set_api_password(self, password: str) -> None:
        """Encrypt and store API password"""
        encrypted = encrypt_model_secret(self, "encrypted_api_password", password)
        self.encrypted_api_password = encrypted.encode()

    def can_host_domain(self) -> bool:
        """Check if server can host another domain (reservation-aware)"""
        from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415  # Circular

        return (
            self.status == "active"
            and not self.is_draining
            and self.is_healthy
            # In-flight migrations targeting this server occupy capacity before
            # current_domains reflects them — every admission path must see it.
            and self.current_domains + VirtualminMigration.active_reservations(self) < self.max_domains
        )


class VirtualminAccount(models.Model):
    """
    Virtualmin virtual server account linked to PRAHO service.

    Represents a Virtualmin virtual server that hosts customer domains.
    Links PRAHO's service management to Virtualmin's hosting infrastructure.

    ARCHITECTURAL DECISION: OneToOne Relationship with Service

    We use OneToOneField instead of ForeignKey because:
    1. **Current Business Logic**: Each PRAHO service should have at most one
       VirtualMin hosting account. This enforces data integrity at the database level.
    2. **Simplified Queries**: service.virtualmin_account provides direct access
       without additional filtering or .first() calls.
    3. **Performance**: OneToOne generates more efficient reverse lookups and
       avoids N+1 query problems in list views.
    4. **Domain Modeling**: Represents the real-world constraint that one service
       maps to one hosting account in our current business model.

    FUTURE MIGRATION PATH:
    If business requirements change to allow multiple VirtualMin accounts per service:
    1. Change OneToOneField to ForeignKey(Service, related_name="virtualmin_accounts")
    2. Update all service.virtualmin_account references to service.virtualmin_accounts.all()
    3. Add filtering logic in views/serializers to handle multiple accounts
    4. Update domain uniqueness constraint to allow multiple accounts per service

    The migration is straightforward since OneToOne is implemented as FK + unique
    constraint, so dropping the unique constraint converts it to ForeignKey.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("provisioning", _("Provisioning")),
        ("active", _("Active")),
        ("suspended", _("Suspended")),
        ("terminated", _("Terminated")),
        ("error", _("Error")),
    )

    # Account identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(
        max_length=255,
        unique=True,  # Database-level uniqueness constraint
        db_index=True,
        verbose_name=_("Primary Domain"),
        help_text=_("Must be unique across all VirtualMin accounts"),
    )

    # Service linkage (OneToOne for current business logic - see class docstring)
    service = models.OneToOneField(
        "provisioning.Service",
        on_delete=models.CASCADE,
        related_name="virtualmin_account",
        verbose_name=_("PRAHO Service"),
        help_text=_(
            "One-to-one relationship ensures each service has at most one VirtualMin account. "
            "This enforces current business logic at database level."
        ),
    )

    # Customer relationship (Cross-app integration)
    customer_membership = models.ForeignKey(
        "users.CustomerMembership",
        on_delete=models.CASCADE,
        null=True,  # Nullable for backwards compatibility
        blank=True,
        related_name="virtualmin_accounts",
        verbose_name=_("Customer Membership"),
        help_text=_("Links hosting account to customer membership for access control"),
    )

    # Server assignment
    server = models.ForeignKey(
        VirtualminServer, on_delete=models.CASCADE, related_name="accounts", verbose_name=_("Virtualmin Server")
    )

    # Virtualmin account details
    virtualmin_username = models.CharField(
        max_length=32,
        unique=True,
        db_index=True,
        verbose_name=_("Virtualmin Username"),
        help_text=_("Unique Virtualmin virtual server username"),
    )
    encrypted_password = models.BinaryField(verbose_name=_("Encrypted Password"))
    template_name = models.CharField(
        max_length=50, default=DEFAULT_VIRTUALMIN_TEMPLATE, verbose_name=_("Virtualmin Template")
    )

    # All domains managed by this account
    domains = models.JSONField(default=list, help_text=_("All domains managed by this Virtualmin account"))

    # Resource limits
    disk_quota_mb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Disk Quota (MB)"))
    effective_disk_quota_mb = models.PositiveIntegerField(
        null=True, blank=True, help_text=_("Desired native cap including headroom; not proof of kernel enforcement")
    )
    quota_generation = models.PositiveBigIntegerField(
        default=0, editable=False, help_text=_("Monotonic native quota execution epoch; never reset on a move")
    )
    quota_managed = models.BooleanField(
        default=False,
        editable=False,
        help_text=_(
            "Explicit account adoption or verified PRAHO creation; node adoption alone never changes existing caps"
        ),
    )
    bandwidth_quota_mb = models.IntegerField(
        null=True, blank=True, verbose_name=_("Bandwidth Quota (MB)"), help_text=_("Use -1 for unlimited bandwidth")
    )

    # Account status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="provisioning", verbose_name=_("Status"))
    status_message = models.TextField(blank=True)

    # Deletion protection
    protected_from_deletion = models.BooleanField(
        default=True,
        verbose_name=_("Protected from Deletion"),
        help_text=_("Prevents accidental deletion of active Virtualmin accounts"),
    )

    # Virtualmin metadata (from PRAHO recovery seeds)
    praho_customer_id = models.PositiveIntegerField(
        null=True, blank=True, help_text=_("Stored in Virtualmin comment for recovery")
    )
    praho_service_id = models.UUIDField(null=True, blank=True, help_text=_("Stored in Virtualmin comment for recovery"))

    # Features enabled
    features = models.JSONField(default=dict, help_text=_("Virtualmin features enabled for this account"))

    # Current usage statistics
    current_disk_usage_mb = models.PositiveIntegerField(default=0)
    current_bandwidth_usage_mb = models.PositiveIntegerField(default=0)

    # Differential-backup chain (docs/domain/virtualmin-incremental-contract.md). Virtualmin keeps one
    # snapshot per domain; the chain is "live" only while this points at the base backup job whose
    # snapshot is still on the node. Anything that can reset or lose the snapshot (a restore, a new
    # base, a migration, a delete) clears it in its admission transaction and bumps the epoch, so a
    # job pinned to an older epoch can never extend a chain that has since been broken.
    chain_base = models.ForeignKey(
        "provisioning.VirtualminProvisioningJob",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("Differential chain base"),
        help_text=_("The base backup job a differential would extend; empty when no chain is live"),
    )
    chain_base_fingerprint = models.CharField(
        max_length=100,
        blank=True,
        default="",
        editable=False,
        help_text=_("Snapshot fingerprint (sha256:size) the base left on the node"),
    )
    chain_epoch = models.PositiveIntegerField(
        default=0, editable=False, help_text=_("Bumped every time the chain is invalidated or restarted")
    )

    # A staff-resolved pair restore that had already restored something leaves a half-restored domain. The
    # reconciler (ADR-0051) and the divergence backstop leave the account alone while this is set, so the
    # site is never brought live by a routine pass; only an explicit staff action clears it: "Re-enable as
    # is", or restoring the safety backup taken before the pair restore.
    restore_hold = models.CharField(
        max_length=30,
        blank=True,
        default="",
        editable=False,
        help_text=_("Why reconcile must leave this account disabled; empty when nothing holds it"),
    )
    restore_hold_safety_backup_id = models.CharField(
        max_length=100,
        blank=True,
        default="",
        editable=False,
        help_text=_("The safety backup taken before the restore that left the domain half-restored"),
    )

    # Timestamps
    provisioned_at = models.DateTimeField(null=True, blank=True)
    # Set once, under a row lock, when the account-name activation email is sent (ADR-0061).
    activation_notified_at = models.DateTimeField(null=True, blank=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AccountOwnershipQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_virtualmin_accounts"
        verbose_name = _("Virtualmin Account")
        verbose_name_plural = _("Virtualmin Accounts")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["domain"]),
            models.Index(fields=["status"]),
            models.Index(fields=["server", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.domain} ({self.get_status_display()})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        fields = kwargs.get("update_fields")
        moved = bool(
            not self._state.adding
            and fields is not None
            and {"server", "server_id"}.intersection(fields)
            and type(self).objects.using(self._state.db).filter(pk=self.pk).exclude(server_id=self.server_id).exists()
        )
        save_with_ownership(self, "account", super().save, args, kwargs)
        if moved:
            from .hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415 -- Canonical node publication.

            ServiceHostingLimits.objects.using(self._state.db).filter(service_id=self.service_id).update(
                verified_at=None
            )

    def get_absolute_url(self) -> str:
        """Get URL for account detail view"""
        return reverse("provisioning:virtualmin_account_detail", kwargs={"account_id": self.id})

    @classmethod
    def from_db(cls, db: str | None, field_names: Collection[str], values: Collection[Any]) -> VirtualminAccount:
        instance = super().from_db(db, field_names, values)
        remember_ownership(instance, "account")
        return instance

    def refresh_from_db(self, *args: Any, **kwargs: Any) -> None:
        super().refresh_from_db(*args, **kwargs)
        fields = kwargs.get("fields", args[1] if len(args) > 1 else None)
        if fields is None or {"service", "service_id"}.intersection(fields):
            remember_ownership(self, "account")

    @property
    def is_active(self) -> bool:
        """Check if account is active"""
        return self.status == "active"

    def get_password(self) -> str:
        """Decrypt and return account password"""
        return decrypt_model_secret(self, "encrypted_password", bytes(self.encrypted_password).decode())

    def set_password(self, password: str) -> None:
        """Encrypt and store account password"""
        encrypted = encrypt_model_secret(self, "encrypted_password", password)
        self.encrypted_password = encrypted.encode()

    def get_recovery_seed(self) -> str:
        """
        Generate the recovery seed stored as the Virtualmin server description.

        Format: "PRAHO=service_id|CID=customer_id|STATUS=status", at most 200
        characters. create-domain takes it as --desc, which refuses ":"
        (Virtualmin 8.x has no --comment option at all).
        """
        parts = []

        if self.praho_service_id:
            parts.append(f"PRAHO={self.praho_service_id}")

        if self.praho_customer_id:
            parts.append(f"CID={self.praho_customer_id}")

        parts.append(f"STATUS={self.status}")

        return "|".join(parts)[:200]  # Truncate to fit Virtualmin comment limit

    @classmethod
    def parse_recovery_seed(cls, seed: str) -> dict[str, Any]:
        """
        Parse a recovery seed from the Virtualmin server description.

        Accepts the current "KEY=value" form and the older "KEY:value" one.

        Args:
            seed: Recovery seed string from Virtualmin

        Returns:
            Dictionary with parsed data
        """
        data: dict[str, uuid.UUID | int | str] = {}

        if not seed or not ("PRAHO=" in seed or "PRAHO:" in seed):
            return data

        try:
            parts = seed.split("|")
            for part in parts:
                separator = "=" if "=" in part else ":"
                if separator in part:
                    key, value = part.split(separator, 1)

                    if key == "PRAHO":
                        with contextlib.suppress(ValueError):
                            data["service_id"] = uuid.UUID(value)
                    elif key == "CID":
                        with contextlib.suppress(ValueError):
                            data["customer_id"] = int(value)
                    elif key == "STATUS":
                        data["status"] = value

        except Exception as e:
            logger.warning(f"Failed to parse recovery seed '{seed}': {e}")

        return data

    @property
    def can_be_deleted(self) -> bool:
        """Check if account can be deleted"""
        return not self.protected_from_deletion

    @property
    def is_suspended(self) -> bool:
        """Check if account is suspended"""
        return self.status == "suspended"

    @property
    def disk_usage(self) -> int:
        """Get current disk usage in bytes for template display"""
        return self.current_disk_usage_mb * 1024 * 1024 if self.current_disk_usage_mb else 0

    @property
    def disk_quota(self) -> int | None:
        """Get disk quota in bytes for template display"""
        return self.disk_quota_mb * 1024 * 1024 if self.disk_quota_mb else None

    @property
    def bandwidth_usage(self) -> int:
        """Get current bandwidth usage in bytes for template display"""
        return self.current_bandwidth_usage_mb * 1024 * 1024 if self.current_bandwidth_usage_mb else 0

    @property
    def bandwidth_quota(self) -> int | None:
        """Get bandwidth quota in bytes for template display"""
        if self.bandwidth_quota_mb == -1:
            return -1  # Unlimited bandwidth
        return self.bandwidth_quota_mb * 1024 * 1024 if self.bandwidth_quota_mb else None

    @property
    def plan(self) -> str:
        """Get service plan name"""
        return self.service.service_plan.name if self.service and self.service.service_plan else "Default"


class VirtualminJobQuerySet(models.QuerySet["VirtualminProvisioningJob"]):
    def update(self, **kwargs: Any) -> int:
        from .hosting_parent_limits import (  # noqa: PLC0415
            PARENT_OPERATIONS,
            PARENT_PROTECTED_FIELDS,
            guard_parent_write,
        )

        if PARENT_PROTECTED_FIELDS.intersection(kwargs):
            changes = {
                "id"
                if key == "pk"
                else key + "_id"
                if key in {"account", "server", "hosting_limit_application"}
                else key: getattr(value, "pk", value)
                for key, value in kwargs.items()
            }
            membership = models.Q(pk__in=[])
            for previous in self.values(
                "id", "operation", "account_id", "server_id", "hosting_limit_application_id", "parameters"
            ):
                guard_parent_write(previous, changes)
                if previous["operation"] in PARENT_OPERATIONS and previous["hosting_limit_application_id"] is not None:
                    membership |= models.Q(
                        pk=previous["id"],
                        parameters=previous["parameters"],
                        operation=previous["operation"],
                        account_id=previous["account_id"],
                        server_id=previous["server_id"],
                        hosting_limit_application_id=previous["hosting_limit_application_id"],
                    )
                else:
                    membership |= models.Q(pk=previous["id"])
            return super(VirtualminJobQuerySet, self.filter(membership)).update(**kwargs)
        return super().update(**kwargs)

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        from .hosting_parent_limits import PARENT_OPERATIONS, PARENT_PROTECTED_FIELDS  # noqa: PLC0415

        records, selected = list(objs), tuple(fields)
        if (
            PARENT_PROTECTED_FIELDS.intersection(selected)
            and self.filter(
                pk__in=[row.pk for row in records],
                operation__in=PARENT_OPERATIONS,
                hosting_limit_application__isnull=False,
            ).exists()
        ):
            raise ValidationError(_("Accepted native parent resource bindings cannot be bulk overwritten."))
        return super().bulk_update(records, selected, batch_size=batch_size)

    def bulk_create(  # noqa: PLR0913 -- Django ORM positional signature.
        self,
        objs: Iterable[VirtualminProvisioningJob],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[VirtualminProvisioningJob]:
        from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415
        from .hosting_parent_limits import PARENT_OPERATIONS  # noqa: PLC0415

        records = list(objs)
        parents = [row for row in records if row.operation in PARENT_OPERATIONS]
        qualified = (
            set(
                NodeHostingPolicy.objects.filter(
                    server_id__in=[row.server_id for row in parents], quota_adopted=True
                ).values_list("server_id", flat=True)
            )
            if parents
            else set()
        )
        if any(row.hosting_limit_application_id is not None or row.server_id in qualified for row in parents) or (
            update_conflicts
            and self.filter(
                pk__in=[row.pk for row in records],
                operation__in=PARENT_OPERATIONS,
                hosting_limit_application__isnull=False,
            ).exists()
        ):
            raise ValidationError(_("Native create and restore admissions must capture resources individually."))
        return super().bulk_create(
            records,
            batch_size=batch_size,
            ignore_conflicts=ignore_conflicts,
            update_conflicts=update_conflicts,
            update_fields=update_fields,
            unique_fields=unique_fields,
        )


class VirtualminProvisioningJob(models.Model):
    """
    Asynchronous Virtualmin provisioning job tracking.

    Tracks provisioning operations for auditing and debugging.
    Supports retry logic and failure analysis.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("running", _("Running")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
        ("cancelled", _("Cancelled")),
        # Non-terminal: an interrupted/uncertain mutation (e.g. a restore whose
        # worker died mid-run). Keeps the account-operation exclusion until an
        # operator resolves it; never auto-recovered.
        ("attention", _("Needs Attention")),
    )

    OPERATION_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("create_domain", _("Create Domain")),
        ("delete_domain", _("Delete Domain")),
        ("modify_domain", _("Modify Domain")),
        ("apply_hosting_limits", _("Apply Hosting Limits")),
        ("suspend_domain", _("Suspend Domain")),
        ("unsuspend_domain", _("Unsuspend Domain")),
        ("create_user", _("Create User")),
        ("delete_user", _("Delete User")),
        ("create_database", _("Create Database")),
        ("delete_database", _("Delete Database")),
        ("install_ssl", _("Install SSL Certificate")),
        ("backup_domain", _("Backup Domain")),
        ("restore_domain", _("Restore Domain")),
        ("migrate_domain", _("Migrate Domain")),
    )

    # Job identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    correlation_id = models.CharField(
        max_length=100, db_index=True, help_text=_("Correlation ID for tracking across systems")
    )

    # Job details
    operation = models.CharField(max_length=30, choices=OPERATION_CHOICES)
    server = models.ForeignKey(VirtualminServer, on_delete=models.CASCADE, related_name="provisioning_jobs")
    account = models.ForeignKey(
        VirtualminAccount, on_delete=models.CASCADE, related_name="provisioning_jobs", null=True, blank=True
    )
    hosting_limit_application = models.ForeignKey(
        "provisioning.HostingLimitApplication",
        on_delete=models.PROTECT,
        related_name="native_jobs",
        null=True,
        blank=True,
    )

    # Job parameters and results
    parameters = models.JSONField(default=dict)
    result = models.JSONField(default=dict)

    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    status_message = models.TextField(blank=True)

    # Retry logic
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    # Leased-claim marker: set when the retry sweep claims this job; a pending
    # job whose lease expired (process death before/after enqueue) is
    # recovered back to failed by the sweep.
    claimed_at = models.DateTimeField(null=True, blank=True)

    # Rollback tracking
    rollback_executed = models.BooleanField(
        default=False, verbose_name=_("Rollback Executed"), help_text=_("Whether rollback was attempted after failure")
    )
    rollback_status = models.CharField(
        max_length=20,
        blank=True,
        choices=(
            ("", _("Not Applicable")),
            ("success", _("Rollback Successful")),
            ("partial", _("Rollback Partially Successful")),
            ("failed", _("Rollback Failed")),
        ),
        verbose_name=_("Rollback Status"),
        help_text=_("Status of rollback operation if executed"),
    )
    rollback_details = models.JSONField(
        default=dict, blank=True, help_text=_("Details of rollback operations performed")
    )

    # Execution tracking
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    # Token-fenced execution (backup/restore): the runner that claimed the job
    # holds the token; terminal writes are conditional on it, so a janitor
    # takeover (which rotates the token) fences out late-returning runners.
    execution_token = models.UUIDField(null=True, blank=True, editable=False)
    execution_deadline = models.DateTimeField(null=True, blank=True)
    execution_time_seconds = models.DecimalField(max_digits=10, decimal_places=3, null=True, blank=True)

    # Django-Q2 task tracking
    task_id = models.CharField(max_length=255, blank=True, db_index=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = VirtualminJobQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_virtualmin_jobs"
        verbose_name = _("Virtualmin Provisioning Job")
        verbose_name_plural = _("Virtualmin Provisioning Jobs")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["status"]),
            models.Index(fields=["operation"]),
            models.Index(fields=["server", "status"]),
            models.Index(fields=["correlation_id"]),
            models.Index(fields=["task_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.get_operation_display()} on {self.server.name} ({self.get_status_display()})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        from .hosting_parent_limits import (  # noqa: PLC0415
            PARENT_PROTECTED_FIELDS,
            guard_parent_write,
            prepare_new_parent,
        )

        with transaction.atomic():
            self.__dict__.pop("_hosting_parent_cas", None)
            fields = kwargs.get("update_fields")
            if fields is None or PARENT_PROTECTED_FIELDS.intersection(fields):
                previous = (
                    type(self)
                    .objects.filter(pk=self.pk)
                    .values("id", "operation", "account_id", "server_id", "hosting_limit_application_id", "parameters")
                    .first()
                )
                if previous is not None:
                    selected = PARENT_PROTECTED_FIELDS if fields is None else fields
                    changes = {
                        "id"
                        if key == "pk"
                        else key + "_id"
                        if key in {"account", "server", "hosting_limit_application"}
                        else key: getattr(
                            self,
                            "id"
                            if key == "pk"
                            else key + "_id"
                            if key in {"account", "server", "hosting_limit_application"}
                            else key,
                        )
                        for key in selected
                        if key in PARENT_PROTECTED_FIELDS
                    }
                    guard_parent_write(previous, changes)
                    if (
                        previous["operation"] in {"create_domain", "restore_domain"}
                        and previous["hosting_limit_application_id"] is not None
                    ):
                        self.__dict__["_hosting_parent_cas"] = previous
                        if fields is None:
                            kwargs["force_update"] = True
            if self._state.adding:
                prepare_new_parent(self)
                if self.hosting_limit_application_id is not None and self.operation in {
                    "create_domain",
                    "restore_domain",
                }:
                    kwargs["force_insert"] = True
            try:
                self._save_with_usage_transition(*args, **kwargs)
            finally:
                self.__dict__.pop("_hosting_parent_cas", None)

    def _do_update(  # noqa: PLR0913 -- Django Model CAS boundary.
        self, base_qs: Any, using: Any, pk_val: Any, values: Any, update_fields: Any, forced_update: Any
    ) -> bool:
        previous = self.__dict__.get("_hosting_parent_cas")
        if previous is not None:
            base_qs = base_qs.filter(
                parameters=previous["parameters"],
                operation=previous["operation"],
                account_id=previous["account_id"],
                server_id=previous["server_id"],
                hosting_limit_application_id=previous["hosting_limit_application_id"],
            )
        return bool(super()._do_update(base_qs, using, pk_val, values, update_fields, forced_update))

    def _save_with_usage_transition(self, *args: Any, **kwargs: Any) -> None:
        fields = kwargs.get("update_fields")
        terminal = self.status in {"completed", "failed", "attention"} and self.completed_at is not None
        if terminal and (fields is None or {"status", "completed_at"}.intersection(fields)):
            with transaction.atomic():
                self._lock_usage_account(self.account_id)
                previous = type(self).objects.filter(pk=self.pk).values_list("status", flat=True).first()
                super().save(*args, **kwargs)
                self._rebind_usage_on_create(self.account_id, self.operation, previous, self.status)
                if previous != self.status:
                    self._invalidate_usage_gauge(self.account_id, self.operation)
        else:
            super().save(*args, **kwargs)

    @classmethod
    def claim_for_retry(cls, job_id: Any, now: Any) -> bool:
        """Leased claim: failed -> pending, consuming one attempt atomically."""
        return bool(
            cls.objects.filter(
                pk=job_id,
                status="failed",
                retry_count__lt=models.F("max_retries"),
                next_retry_at__lte=now,
            ).update(status="pending", retry_count=models.F("retry_count") + 1, claimed_at=now, updated_at=now)
        )

    @classmethod
    def start_claimed(cls, job_id: Any, now: Any, claim_nonce: str | None = None) -> bool:
        """Fence at execution: pending -> running, optionally bound to the
        claim nonce (claimed_at isoformat) so a delivery from a recovered and
        re-issued claim cannot steal the new claim. 0 rows = stale delivery."""
        if claim_nonce:
            claimed_at = cls.objects.filter(pk=job_id).values_list("claimed_at", flat=True).first()
            if claimed_at is None or claimed_at.isoformat() != claim_nonce:
                return False
        return bool(
            cls.objects.filter(pk=job_id, status="pending").update(status="running", started_at=now, updated_at=now)
        )

    @classmethod
    def recover_expired_claims(cls, cutoff: datetime, retry_at: datetime, *, now: datetime | None = None) -> int:
        """Recover pending dispatch leases and expired running execution budgets.

        Pending jobs and legacy jobs without a persisted budget keep the age-based
        lease. A budgeted running job gets its full budget from started_at, plus
        a minute for worker termination. Older rows fall back to claim/update time.
        """
        recovery_time = timezone.now() if now is None else now
        jobs = (
            cls.objects.filter(status__in=("pending", "running"))
            # Backup/restore have their own execution_deadline and janitor.
            .exclude(operation__in=("backup_domain", "restore_domain", "apply_hosting_limits"))
            .only("operation", "status", "parameters", "claimed_at", "started_at", "updated_at")
        )
        recovered = 0
        for job in jobs.iterator():
            budget: object = job.parameters.get("task_budget_seconds")
            if job.status == "running" and isinstance(budget, int) and budget > 0:
                started_at = job.started_at or job.claimed_at or job.updated_at
                deadline = started_at + timedelta(seconds=budget + _EXECUTION_RECOVERY_MARGIN_SECONDS)
                expired = deadline < recovery_time
            else:
                lease_started_at = job.claimed_at or job.started_at or job.updated_at
                expired = lease_started_at < cutoff
            if expired:
                # Fence against a worker completing, starting or refreshing the row
                # after this sweep read it.
                fenced = cls.objects.filter(
                    pk=job.pk,
                    status=job.status,
                    claimed_at=job.claimed_at,
                    started_at=job.started_at,
                    updated_at=job.updated_at,
                )
                receipt_off = job.operation == "suspend_domain" and "revoked_create_job_id" in (job.parameters or {})
                if receipt_off:
                    retired = cls._retire_closed_receipt(job)
                    if retired is not None:
                        recovered += retired
                        continue
                exhausted_dispatch = receipt_off and job.status == "pending" and job.retry_count >= job.max_retries
                if exhausted_dispatch or (
                    job.status == "running" and (job.operation in UNCERTAIN_WHEN_INTERRUPTED_OPERATIONS or receipt_off)
                ):
                    # A dead delete worker may have deleted the domain: replaying it blind, and
                    # releasing the account's exclusion, is not safe. An operator resolves it.
                    recovered += cls._recover_usage_fenced(
                        job,
                        fenced,
                        status="attention",
                        status_message=(
                            "Receipt-bound OFF dispatch budget exhausted; operator verification required"
                            if exhausted_dispatch
                            else "Worker interrupted; execution deadline exceeded"
                        ),
                        next_retry_at=None,
                        claimed_at=None,
                        updated_at=recovery_time,
                    )
                else:
                    recovered += cls._recover_usage_fenced(
                        job, fenced, status="failed", next_retry_at=retry_at, claimed_at=None, updated_at=recovery_time
                    )
        return recovered

    @classmethod
    def _recover_usage_fenced(
        cls, job: VirtualminProvisioningJob, fenced: models.QuerySet[VirtualminProvisioningJob], **values: Any
    ) -> int:
        with transaction.atomic():
            cls._lock_usage_account(job.account_id)
            changed = fenced.update(**values)
            if changed:
                cls._invalidate_usage_gauge(job.account_id, job.operation)
            return changed

    @classmethod
    def restore_after_enqueue_failure(cls, job_id: Any, retry_at: Any, *, claimed_at: Any = None) -> int:
        """Return a claimed-but-undispatched job to the failed pool."""
        pending = cls.objects.filter(pk=job_id, status="pending")
        if claimed_at is not None:
            pending = pending.filter(claimed_at=claimed_at)
        receipt_off = pending.filter(
            operation="suspend_domain",
            parameters__revoked_create_job_id__isnull=False,
        )
        snapshot = receipt_off.first()
        if snapshot is not None:
            retired = cls._retire_closed_receipt(snapshot)
            if retired is not None:
                return retired
            pending = pending.filter(
                claimed_at=snapshot.claimed_at,
                started_at=snapshot.started_at,
                updated_at=snapshot.updated_at,
            )
            if snapshot.retry_count >= snapshot.max_retries:
                return pending.update(
                    status="attention",
                    claimed_at=None,
                    next_retry_at=None,
                    updated_at=timezone.now(),
                    status_message="Receipt-bound OFF dispatch budget exhausted; operator verification required",
                )
        return pending.update(status="failed", claimed_at=None, next_retry_at=retry_at, updated_at=timezone.now())

    @staticmethod
    def _retire_closed_receipt(job: VirtualminProvisioningJob) -> int | None:
        from .virtualmin_revoked_create import retire_closed_off_claim  # noqa: PLC0415  # Circular models.

        retired = retire_closed_off_claim(job)
        if retired.is_err():
            return 0
        return 1 if retired.unwrap() else None

    @classmethod
    def terminalize(cls, job_id: Any) -> int:
        """Opt a job out of the retry sweep permanently (existing convention)."""
        return cls.objects.filter(pk=job_id).update(next_retry_at=None, updated_at=timezone.now())

    @classmethod
    def record_dispatch(cls, job_id: Any, task_id: str) -> int:
        """Persist the queue task id for the dispatched retry."""
        return cls.objects.filter(pk=job_id).update(task_id=task_id, updated_at=timezone.now())

    # ------------------------------------------------------------------
    # Token-fenced execution protocol (backup/restore jobs)
    # ------------------------------------------------------------------

    @classmethod
    def claim_execution(cls, job_id: Any, token: Any, deadline: Any) -> int:
        """CAS pending→running; duplicate deliveries and reaper races yield one owner."""
        return cls.objects.filter(pk=job_id, status="pending").update(
            status="running",
            started_at=timezone.now(),
            execution_token=token,
            execution_deadline=deadline,
            updated_at=timezone.now(),
        )

    @classmethod
    def owns_execution(cls, job_id: Any, token: Any) -> bool:
        """Stage-boundary ownership check: token unchanged and deadline unexpired."""
        return cls.objects.filter(pk=job_id, execution_token=token, execution_deadline__gt=timezone.now()).exists()

    @classmethod
    def finish_execution(
        cls,
        job_id: Any,
        token: Any,
        status: str,
        message: str,
        result: dict[str, Any] | None = None,
    ) -> int:
        """Token-fenced terminal write; a rotated token makes this a no-op."""
        payload = without_secrets(dict(result or {}))
        with transaction.atomic():
            job = cls.objects.filter(pk=job_id, execution_token=token).first()
            if job is None:
                return 0
            cls._lock_usage_account(job.account_id)
            previous = cls.objects.filter(pk=job_id).values_list("status", flat=True).first()
            changed = cls.objects.filter(pk=job_id, execution_token=token).update(
                status=status,
                status_message=message,
                completed_at=timezone.now(),
                result=payload,
                next_retry_at=None,
                updated_at=timezone.now(),
            )
            if changed:
                cls._rebind_usage_on_create(job.account_id, job.operation, previous, status)
                if previous != status:
                    cls._invalidate_usage_gauge(job.account_id, job.operation)
            return changed

    @classmethod
    def take_over_execution(cls, job_id: Any, status: str, message: str) -> int:
        """Janitor takeover: rotate the token in the same CAS that writes the status."""
        with transaction.atomic():
            job = cls.objects.filter(pk=job_id, status="running").first()
            if job is None:
                return 0
            cls._lock_usage_account(job.account_id)
            changed = cls.objects.filter(pk=job_id, status="running").update(
                status=status,
                status_message=message,
                execution_token=uuid.uuid4(),
                completed_at=timezone.now(),
                next_retry_at=None,
                updated_at=timezone.now(),
            )
            if changed:
                cls._rebind_usage_on_create(job.account_id, job.operation, "running", status)
                cls._invalidate_usage_gauge(job.account_id, job.operation)
            return changed

    @staticmethod
    def _lock_usage_account(account_id: Any) -> None:
        if account_id is not None:
            VirtualminAccount.objects.select_for_update(no_key=True).filter(pk=account_id).first()

    @staticmethod
    def _rebind_usage_on_create(account_id: Any, operation: str, previous: str | None, status: str) -> None:
        if (
            account_id is not None
            and operation == "create_domain"
            and status == "completed"
            and previous != "completed"
        ):
            from .virtualmin_usage_service import rebind_created_account  # noqa: PLC0415

            rebind_created_account(account_id)

    @staticmethod
    def _invalidate_usage_gauge(account_id: Any, operation: str) -> None:
        if account_id is not None and operation in {"restore_domain", "create_domain", "delete_domain"}:
            from .virtualmin_usage_service import invalidate_gauge  # noqa: PLC0415

            invalidate_gauge(account_id)

    @property
    def can_retry(self) -> bool:
        """Check if job can be retried"""
        return self.status == "failed" and self.retry_count < self.max_retries

    def mark_started(self) -> None:
        """Mark job as started"""
        self.status = "running"
        self.started_at = timezone.now()
        self.save(update_fields=["status", "started_at", "updated_at"])

    def mark_completed(self, result: dict[str, Any], rollback_operations: list[dict[str, Any]] | None = None) -> None:
        """Mark job as completed successfully"""
        now = timezone.now()
        self.status = "completed"
        self.completed_at = now
        self.result = without_secrets(dict(result))

        # Store rollback operations for potential future use
        if rollback_operations and "rollback_operations" not in self.result:
            self.result["rollback_operations"] = rollback_operations

        if self.started_at:
            duration = now - self.started_at
            self.execution_time_seconds = Decimal(str(duration.total_seconds()))

        self.save(update_fields=["status", "completed_at", "result", "execution_time_seconds", "updated_at"])
        self._queue_line_fulfilment()

    def mark_attention(self, error_message: str, result: dict[str, Any] | None = None) -> None:
        """Park an uncertain mutation for an operator instead of failing it.

        The command may already have run, so the job neither retries nor releases the account's
        operation exclusion (``attention`` is an active status); it stays until resolved.
        """
        now = timezone.now()
        self.status = "attention"
        self.status_message = error_message
        self.completed_at = now
        self.result = {**without_secrets(dict(result or self.result or {})), "retriability": Retriability.UNKNOWN.value}
        self.next_retry_at = None
        if self.started_at:
            self.execution_time_seconds = Decimal(str((now - self.started_at).total_seconds()))
        self.save(
            update_fields=[
                "status",
                "status_message",
                "completed_at",
                "result",
                "execution_time_seconds",
                "next_retry_at",
                "updated_at",
            ]
        )
        self._queue_line_fulfilment()

    def settle_failure(
        self, error_message: str, result: dict[str, Any] | None = None, *, retriability: Retriability
    ) -> None:
        """Fail the job, or park it when an UNKNOWN outcome leaves a destructive command uncertain."""
        if retriability is Retriability.UNKNOWN and self.operation in UNCERTAIN_WHEN_INTERRUPTED_OPERATIONS:
            self.mark_attention(error_message, result)
        else:
            self.mark_failed(error_message, result, retriability=retriability)

    def mark_failed(  # noqa: PLR0913  # Cohesive persisted failure transition
        self,
        error_message: str,
        result: dict[str, Any] | None = None,
        rollback_executed: bool = False,
        rollback_status: str = "",
        rollback_details: dict[str, Any] | None = None,
        retriability: Retriability = Retriability.UNKNOWN,
    ) -> None:
        """
        Mark job as failed with optional rollback tracking.

        Args:
            error_message: Error description
            result: Additional result data
            rollback_executed: Whether rollback was attempted
            rollback_status: Status of rollback ("success", "partial", "failed")
            rollback_details: Details of rollback operations performed
            retriability: Whether an automatic replay is known to be safe
        """
        now = timezone.now()
        self.status = "failed"
        self.status_message = error_message
        self.completed_at = now

        if result:
            self.result = without_secrets(dict(result))
        else:
            self.result = dict(self.result or {})
        self.result["retriability"] = retriability.value

        # Track rollback information
        self.rollback_executed = rollback_executed
        if rollback_executed:
            self.rollback_status = rollback_status
            self.rollback_details = rollback_details or {}

        if self.started_at:
            duration = now - self.started_at
            self.execution_time_seconds = Decimal(str(duration.total_seconds()))

        # Only explicit safe-to-replay failures enter the automatic retry sweep.
        # UNKNOWN includes lost responses where a mutation may already have run.
        self.next_retry_at = None
        if retriability is Retriability.RETRIABLE and self.can_retry:
            # Exponential backoff: 2^retry_count minutes
            backoff_minutes = 2**self.retry_count
            self.next_retry_at = now + timedelta(minutes=backoff_minutes)

        self.save(
            update_fields=[
                "status",
                "status_message",
                "completed_at",
                "result",
                "execution_time_seconds",
                "next_retry_at",
                "rollback_executed",
                "rollback_status",
                "rollback_details",
                "updated_at",
            ]
        )
        self._queue_line_fulfilment()

    def _queue_line_fulfilment(self) -> None:
        """A settled create job lets the order line that bought the account move on.

        It only enqueues, after commit. No order bookkeeping runs in the account's own transaction, so
        nothing here can raise into the create's remote-rollback handling.
        """
        if self.operation == "create_domain" and self.account_id is not None:
            account_id = self.account_id
            transaction.on_commit(lambda: _enqueue_line_fulfilment(account_id), robust=True)


def _enqueue_line_fulfilment(account_id: uuid.UUID) -> None:
    """Queue apps.orders' line fulfilment for the open lines of the account's Service."""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415

        from apps.orders.models import OrderItem  # noqa: PLC0415  # ADR-0007: cross-app at call time
        from apps.orders.tasks import get_task_time_limit  # noqa: PLC0415

        service_id = VirtualminAccount.objects.filter(pk=account_id).values_list("service_id", flat=True).first()
        if service_id is None:
            return
        open_lines = (
            OrderItem.objects.filter(service_id=service_id, provisioning_status__in=("pending", "in_progress"))
            .exclude(product_type="domain")
            .values_list("pk", flat=True)
        )
        for item_id in open_lines:
            async_task("apps.orders.tasks.provision_order_item", str(item_id), timeout=get_task_time_limit())
    except Exception:
        # The order-line recovery sweep finishes the line; the account and its job are already settled.
        logger.exception("🔥 [Virtualmin] Could not queue line fulfilment for account %s", account_id)


class VirtualminDriftRecord(models.Model):
    """
    Records drift detection between PRAHO and Virtualmin state.

    Tracks discrepancies for auditing and automated reconciliation.
    """

    DRIFT_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("missing_in_virtualmin", _("Missing in Virtualmin")),
        ("missing_in_praho", _("Missing in PRAHO")),
        ("status_mismatch", _("Status Mismatch")),
        ("quota_mismatch", _("Quota Mismatch")),
        ("feature_mismatch", _("Feature Mismatch")),
        ("metadata_mismatch", _("Metadata Mismatch")),
    )

    RESOLUTION_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("auto_fixed", _("Auto Fixed")),
        ("manual_fixed", _("Manual Fixed")),
        ("ignored", _("Ignored")),
    )

    # Drift identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(max_length=255, db_index=True)
    server = models.ForeignKey(VirtualminServer, on_delete=models.CASCADE)

    # Drift details
    drift_type = models.CharField(max_length=30, choices=DRIFT_TYPE_CHOICES)
    description = models.TextField()
    praho_state = models.JSONField(default=dict)
    virtualmin_state = models.JSONField(default=dict)

    # Resolution
    resolution_status = models.CharField(max_length=20, choices=RESOLUTION_CHOICES, default="pending")
    resolution_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, blank=True)

    # Timestamps
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "provisioning_virtualmin_drift_records"
        verbose_name = _("Virtualmin Drift Record")
        verbose_name_plural = _("Virtualmin Drift Records")
        ordering: ClassVar[tuple[str, ...]] = ("-detected_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["domain"]),
            models.Index(fields=["drift_type"]),
            models.Index(fields=["resolution_status"]),
            models.Index(fields=["server", "resolution_status"]),
        ]

    def __str__(self) -> str:
        return f"{self.domain}: {self.get_drift_type_display()}"
