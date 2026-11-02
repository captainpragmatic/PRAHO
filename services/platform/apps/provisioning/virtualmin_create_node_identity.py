"""Keep original-create recovery bound to its recorded node and retry claim."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result

from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity


@transaction.atomic
def lock_create_retry_node(account: VirtualminAccount, job: VirtualminProvisioningJob) -> Result[VirtualminServer, str]:
    """Recheck before observation and under the transaction settling its result.

    Observation can recover an existing resource after destination admission is
    withdrawn. It cannot transfer that result to a different node incarnation.
    The caller keeps these locks through local settlement, never native I/O.
    """
    VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=account.pk)
    server = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=job.server_id)
    current = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=job.pk)
    expected = (job.status, job.claimed_at, job.started_at, job.account_id, job.server_id, job.operation)
    actual = (
        current.status,
        current.claimed_at,
        current.started_at,
        current.account_id,
        current.server_id,
        current.operation,
    )
    if (
        job.account_id != account.pk
        or actual != expected
        or current.parameters.get("node_connection_identity") != job.parameters.get("node_connection_identity")
    ):
        return Err(_("The original create no longer owns its recovery claim."))

    recorded = current.parameters.get("node_connection_identity")
    refusal: str | None
    if server.security_operation:
        refusal = _("Resolve the node's hardening attempt before recovering its original create.")
    elif recorded is None:
        # Old jobs retain their admitted-node behavior. An unverified legacy
        # target has no receipt authorizing recovery across policy withdrawal.
        refusal = destination_refusal(server)
    else:
        try:
            unchanged = recorded == connection_identity(server)
        except ValidationError:
            unchanged = False
        refusal = (
            None
            if unchanged
            else _("The original create node identity changed. Verify its recorded target and outcome before retrying.")
        )
    if refusal:
        if current.status == "running":
            current.mark_attention(
                refusal,
                {
                    **current.result,
                    "creation_node_review": {"server_id": str(server.pk), "phase": "identity_review"},
                },
            )
        return Err(refusal)
    return Ok(server)
