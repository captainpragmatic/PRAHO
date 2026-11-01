"""Bind a retry's observed native outcome to its original account and target."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .virtualmin_create_retry_policy import creation_service_binding_matches
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_revoked_create import RECEIPT_KEY

logger = logging.getLogger(__name__)


def password_fingerprint(account: VirtualminAccount) -> str:
    """Identify the persisted sealed credential generation, without exposing it."""
    return hashlib.sha256(bytes(account.encrypted_password)).hexdigest()


@dataclass(frozen=True)
class CreateRetryBinding:
    account_id: UUID
    service_id: int
    origin_server_id: UUID
    target_server_id: UUID
    domain: str
    owner: str
    password_fingerprint: str
    job_status: str
    claimed_at: datetime | None
    started_at: datetime | None

    def owns(self, account: VirtualminAccount, job: VirtualminProvisioningJob) -> bool:
        return (
            account.pk == self.account_id
            and account.service_id == self.service_id
            and account.server_id == self.origin_server_id
            and account.domain == self.domain
            and account.virtualmin_username == self.owner
            and password_fingerprint(account) == self.password_fingerprint
            and job.account_id == self.account_id
            and RECEIPT_KEY not in (job.result or {})
            and creation_service_binding_matches(self.service_id, job)
            and job.server_id == self.target_server_id
            and job.status == self.job_status
            and job.claimed_at == self.claimed_at
            and job.started_at == self.started_at
            and job.parameters.get("domain", self.domain) == self.domain
            and job.parameters.get("username", self.owner) == self.owner
            and job.parameters.get("creation_credential_generation", self.password_fingerprint)
            == self.password_fingerprint
        )


def retry_binding(account: VirtualminAccount, job: VirtualminProvisioningJob) -> CreateRetryBinding | None:
    """Only the actual reprovision producer may authorize a staged target."""
    expected_claim = (job.status, job.claimed_at, job.started_at)
    account.refresh_from_db()
    job.refresh_from_db()
    if expected_claim != (job.status, job.claimed_at, job.started_at) or job.status not in (
        "running",
        "failed",
        "completed",
    ):
        return None
    intent = job.parameters.get("creation_intent")
    staged_without_origin = account.server_id != job.server_id and (
        not isinstance(intent, dict)
        or intent.get("purpose") != "reprovision"
        or job.parameters.get("reprovision_source_server_id") != str(account.server_id)
    )
    binding = CreateRetryBinding(
        account.pk,
        account.service_id,
        account.server_id,
        job.server_id,
        account.domain,
        account.virtualmin_username,
        password_fingerprint(account),
        job.status,
        job.claimed_at,
        job.started_at,
    )
    if not staged_without_origin and binding.owns(account, job):
        return binding
    park_changed_binding(binding, job.pk, native_outcome="not_observed")
    return None


def binding_current(binding: CreateRetryBinding, job_id: UUID) -> bool:
    account = VirtualminAccount.objects.get(pk=binding.account_id)
    job = VirtualminProvisioningJob.objects.get(pk=job_id)
    return binding.owns(account, job)


def park_changed_binding(binding: CreateRetryBinding, job_id: UUID, *, native_outcome: str) -> None:
    """Park only the original delivery; preserve a reaper or a newer claim."""
    with transaction.atomic():
        VirtualminAccount.objects.select_for_update().get(pk=binding.account_id)
        job = VirtualminProvisioningJob.objects.select_for_update().get(pk=job_id)
        if (
            job.status == binding.job_status
            and job.claimed_at == binding.claimed_at
            and job.started_at == binding.started_at
        ):
            job.mark_attention(
                "Original create account binding changed; verify the recorded native target",
                {
                    **job.result,
                    "creation_review": {
                        "domain": binding.domain,
                        "owner": binding.owner,
                        "server_id": str(binding.target_server_id),
                        "native_outcome": native_outcome,
                    },
                },
            )


def settle_retry_created(
    binding: CreateRetryBinding, job_id: UUID, data: dict[str, Any], *, native_outcome: str
) -> Result[dict[str, Any], str]:
    try:
        return _settle_retry_created(binding, job_id, data, native_outcome=native_outcome)
    except Exception:
        logger.exception("Native creation settlement needs review for job %s", job_id)
        park_changed_binding(binding, job_id, native_outcome=native_outcome)
        return Err("Native creation succeeded but local settlement needs operator review")


def _settle_retry_created(
    binding: CreateRetryBinding, job_id: UUID, data: dict[str, Any], *, native_outcome: str
) -> Result[dict[str, Any], str]:
    """Commit verified target/count once; preserve a real resource on stale settlement."""
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=binding.account_id)
        job = VirtualminProvisioningJob.objects.select_for_update().get(pk=job_id)
        if not binding.owns(account, job):
            # A reaper/new owner remains authoritative. Never resurrect its job.
            if (
                job.status == binding.job_status
                and job.claimed_at == binding.claimed_at
                and job.started_at == binding.started_at
            ):
                job.mark_attention(
                    "Native create outcome has a changed account binding; verify the recorded target",
                    {
                        **job.result,
                        "creation_review": {
                            "domain": binding.domain,
                            "owner": binding.owner,
                            "server_id": str(binding.target_server_id),
                            "native_outcome": native_outcome,
                        },
                    },
                )
            return Err("Native create outcome no longer owns its account/claim binding")
        # Previously verified on the same target is already counted, including
        # a domain subsequently disabled by a policy recovery.
        counted = account.provisioned_at is not None and account.server_id == binding.target_server_id
        account.server_id = binding.target_server_id
        account.status = "active"  # fsm-bypass: CharField status
        account.status_message = ""
        account.provisioned_at = account.provisioned_at or timezone.now()
        account.save(update_fields=["server", "status", "status_message", "provisioned_at", "updated_at"])
        if not counted:
            VirtualminServer.objects.filter(pk=binding.target_server_id).update(
                current_domains=models.F("current_domains") + 1, updated_at=timezone.now()
            )
        job.mark_completed(data)
    return Ok(data)
