"""Serialize drift expiry with an operator's provider restore-point retention decision."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Literal

from django.db import transaction

from . import cloud_gateway, provider_config
from .cloud_destroy_models import CloudResourceRetention
from .deployment_lifecycle import provider_token_fingerprint
from .models import DriftSnapshot, NodeDeployment

logger = logging.getLogger(__name__)
ExpiryOutcome = Literal["deleted", "failed", "retained", "not_expired"]


@transaction.atomic
def expire_snapshot(candidate: DriftSnapshot, now: datetime) -> ExpiryOutcome:
    # Approval takes this same deployment lock. Hold it through provider confirmation: approval
    # either protects a still-existing image first, or observes that deletion already completed.
    deployment = NodeDeployment.objects.select_for_update().get(pk=candidate.deployment_id)
    snapshot = DriftSnapshot.objects.select_for_update().get(pk=candidate.pk)
    if snapshot.status != "available" or snapshot.expires_at is None or snapshot.expires_at > now:
        return "not_expired"
    token = provider_config.get_provider_token(deployment.provider)
    if token.is_err():
        return "failed"
    fingerprint = provider_token_fingerprint(token.unwrap())
    if not deployment.provider_token_fingerprint or deployment.provider_token_fingerprint != fingerprint:
        snapshot.status = "cleanup_failed"
        snapshot.save(update_fields=["status"])
        # nosemgrep: python-logger-credential-disclosure — Only a static message and snapshot UUID are logged; never the credential.
        logger.warning("⚠️ [Snapshot expiry] Creating provider credential is unproven for snapshot %s", snapshot.pk)
        return "failed"
    if CloudResourceRetention.objects.filter(
        provider_id=deployment.provider_id,
        token_fingerprint=fingerprint,
        kind__in=("snapshot", "volume_snapshot"),
        resource_id=snapshot.provider_snapshot_id,
    ).exists():
        return "retained"
    gateway = cloud_gateway.get_cloud_gateway(deployment.provider.provider_type, token.unwrap())
    result = gateway.delete_snapshot(snapshot.provider_snapshot_id)
    if result.is_ok() and result.unwrap() is True:
        snapshot.status = "deleted"
        snapshot.save(update_fields=["status"])
        return "deleted"
    snapshot.status = "cleanup_failed"
    snapshot.save(update_fields=["status"])
    logger.warning("⚠️ [Snapshot expiry] Snapshot %s deletion is unconfirmed", snapshot.pk)
    return "failed"
