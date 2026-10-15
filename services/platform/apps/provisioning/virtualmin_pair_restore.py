"""Pair restore: a base backup and its differential restored as one workflow (plan section 4, R2-5).

A differential holds only what changed since its base, so a domain is restored from the pair:
the base first, then the differential. Facts the labels must state plainly (contract Q5/Q6):
files deleted after the base was taken reappear, and databases come from the differential's
full dump.

The workflow, in order, and what each stage may leave behind:

1. admission (``VirtualminBackupManagementService.create_pair_restore_job``): account lock,
   exclusion, chain invalidation, budget over both archives and every stage;
2. preflight, before anything destructive: both archives downloaded and their checksums verified,
   exact lineage and roles, ``diff.fp_before == base.fp_after``, no differential of a
   differential, known manifest versions only;
3. one standalone safety backup of the target;
4. both archives pushed to the node's private staging directory;
5. ONE locked node execution (files/praho-pair-restore.sh) behind a two-layer write barrier: a
   maintenance virtual host answering 503 plus disable-domain, re-applied and verified after
   each restore step;
6. verification. The domain is left disabled: PRAHO's reconcile (ADR-0051) enables it again.

Any failure after the barrier keeps it up and sends the job to attention with the checkpoints
the node reached; ownership is rechecked before every destructive call, and the node checks the
job's cancel marker before each restore.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.settings.services import SettingsService

from .virtualmin_chain import (
    CHAIN_DOMAIN_ID_PATTERN,
    CHAIN_RUN_ID_PATTERN,
    ROLE_BASE,
    ROLE_DIFFERENTIAL,
    deployment_destroyed,
    invalidate_chain,
    is_chain_domain,
    node_lost_refusal,
)
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from .virtualmin_backup_service import RestoreConfig, VirtualminBackupService

logger = logging.getLogger(__name__)

PAIR_PLAYBOOK = "virtualmin_pair_restore.yml"
RESTORE_MODE_PAIR = "pair"
PAIR_LOCK_WAIT_SECONDS = 60
PAIR_NODE_MARGIN_SECONDS = 600
PAIR_VERIFY_MARGIN_SECONDS = 300

# Said to the operator wherever a pair restore can be chosen.
PAIR_RESTORE_LABEL = _(
    "Restores the base backup and then the differential. Files deleted after the base was "
    "taken will reappear, and databases come from the differential's full dump. The domain is "
    "taken offline (maintenance page and disabled) until the restore is verified."
)

_PAIR_RESULT_RE = re.compile(r"PAIR_RESULT=([A-Za-z0-9+/=]+)")
_PAIR_OUTCOMES = frozenset({"ok", "refused", "failed", "released"})
_HTTP_CODE_RE = re.compile(r"^(none|[0-9]{3})$")
_STEP_RE = re.compile(r"^[a-z_]{1,40}$")


def is_pair_job(operation: str, parameters: Mapping[str, Any]) -> bool:
    """True for a restore job that restores a base and a differential together."""
    return operation == "restore_domain" and str(parameters.get("restore_mode", "")) == RESTORE_MODE_PAIR


@dataclass(frozen=True)
class PairCheckpoint:
    """What the node saw at one point: is the domain disabled, and what do the two ports answer."""

    step: str
    at: str
    disabled: bool
    http80: str
    http443: str

    @property
    def barrier_holds(self) -> bool:
        return self.disabled and self.http80 == "503" and self.http443 in ("none", "503")

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "at": self.at,
            "disabled": self.disabled,
            "http80": self.http80,
            "http443": self.http443,
        }


@dataclass(frozen=True)
class PairStepResult:
    """The one result line of the node-side pair step."""

    outcome: str
    reason: str
    ran: bool
    checkpoints: tuple[PairCheckpoint, ...]

    def checkpoint_dicts(self) -> list[dict[str, Any]]:
        return [checkpoint.as_dict() for checkpoint in self.checkpoints]

    def barrier_broken(self) -> str | None:
        """Why a result that claims success cannot be believed, or None.

        Every checkpoint must show the domain disabled; every one taken while the maintenance host
        was supposed to be up must show it answering 503. (The last checkpoint is taken after the
        maintenance host came down and only has to show the domain still disabled.)
        """
        for checkpoint in self.checkpoints:
            if checkpoint.step == "barrier_down":
                if not checkpoint.disabled:
                    return "the domain was enabled when the barrier came down"
            elif not checkpoint.barrier_holds:
                return f"the barrier did not hold at {checkpoint.step}"
        return None


def parse_pair_step_result(stdout: str, *, token: str, domain_id: str, action: str) -> Result[PairStepResult, str]:  # noqa: PLR0911  # One exit per way a result line can be unusable
    """Parse and cross-check the single result line; anything else is uncertain."""

    def uncertain(message: str) -> Err[str]:
        return Err(f"Pair step result unusable: {message}", retriability=Retriability.UNKNOWN)

    encoded = set(_PAIR_RESULT_RE.findall(stdout))
    if len(encoded) != 1:
        return uncertain(f"expected exactly one result line, found {len(encoded)}")
    try:
        payload = json.loads(base64.b64decode(encoded.pop(), validate=True))
    except ValueError:
        return uncertain("not decodable")
    if not isinstance(payload, dict):
        return uncertain("not an object")
    if (payload.get("token"), payload.get("domain_id"), payload.get("action")) != (token, domain_id, action):
        return uncertain("it names a different run")
    try:
        raw_checkpoints = payload["checkpoints"]
        checkpoints = tuple(
            PairCheckpoint(
                step=str(item["step"]),
                at=str(item["at"]),
                disabled=item["disabled"] is True,
                http80=str(item["http80"]),
                http443=str(item["http443"]),
            )
            for item in raw_checkpoints
        )
        step = PairStepResult(
            outcome=str(payload["outcome"]),
            reason=str(payload["reason"]),
            ran=payload["ran"] is True,
            checkpoints=checkpoints,
        )
    except (KeyError, TypeError, ValueError):
        return uncertain("missing or malformed field")
    if step.outcome not in _PAIR_OUTCOMES:
        return uncertain(f"unknown outcome {step.outcome!r}")
    for checkpoint in checkpoints:
        if not (
            _STEP_RE.match(checkpoint.step)
            and _HTTP_CODE_RE.match(checkpoint.http80)
            and _HTTP_CODE_RE.match(checkpoint.http443)
        ):
            return uncertain("malformed checkpoint")
    return Ok(step)


# ---------------------------------------------------------------------------- lineage


_COMPONENT_FLAGS = ("include_email", "include_databases", "include_files", "include_ssl")


def pair_lineage_refusal(  # noqa: C901, PLR0911, PLR0912  # One exit per way a pair can be unrestorable
    base: Mapping[str, Any], differential: Mapping[str, Any], *, service_id: object, domain: str
) -> str | None:
    """Why these two manifests are not a restorable pair for this account, or None.

    Exact lineage: the differential names this base, was taken against the snapshot the base
    left (``diff.fp_before == base.fp_after``), both are complete backups of every component of
    the same account, domain id, node and chain epoch, and both are of versions and roles this
    release knows. A differential of a differential is not a pair.
    """
    from .virtualmin_backup_service import manifest_lineage_role  # noqa: PLC0415  # Circular

    roles: dict[str, str] = {}
    for label, manifest in (("base", base), ("differential", differential)):
        role = manifest_lineage_role(manifest)
        if role.is_err():
            return f"The {label} backup is not understood: {role.unwrap_err()}"
        roles[label] = role.unwrap()
    if roles["base"] != ROLE_BASE:
        return "The first backup is not a base backup"
    if roles["differential"] != ROLE_DIFFERENTIAL:
        return "The second backup is not a differential backup"
    if base.get("manifest_version") is None or differential.get("manifest_version") is None:
        return "A legacy backup cannot be part of a pair"
    if base.get("base_backup_id"):
        return "The base itself names a base; a differential of a differential is not a pair"
    if not base.get("backup_id") or differential.get("base_backup_id") != base.get("backup_id"):
        return "The differential does not name this base backup"
    fp_after, fp_before = str(base.get("fp_after") or ""), str(differential.get("fp_before") or "")
    if not fp_after or fp_after == "ABSENT" or fp_before != fp_after:
        return "The differential was not taken against the snapshot this base left"
    for label, manifest in (("base", base), ("differential", differential)):
        if manifest.get("status") != "completed":
            return f"The {label} backup is not complete"
        if any(manifest.get(flag) is not True for flag in _COMPONENT_FLAGS):
            return f"The {label} backup does not hold every component"
        if str(manifest.get("praho_service_id")) != str(service_id) or manifest.get("domain") != domain:
            return f"The {label} backup belongs to another account or domain"
    for key in ("virtualmin_domain_id", "node_id", "chain_epoch"):
        if base.get(key) in (None, "") or base.get(key) != differential.get(key):
            return f"The two backups disagree on {key.replace('_', ' ')}"
    return None


def pair_restore_task_timeout(estimated_bytes: int, base_bytes: int, differential_bytes: int) -> int:
    """Task budget over EVERY stage: safety backup, two downloads, two pushes, the node step, verification."""
    from .virtualmin_backup_service import (  # noqa: PLC0415  # Circular
        _S3_COMPLETION_MARGIN_SECONDS,
        _SSH_SETUP_MARGIN_SECONDS,
        backup_task_timeout,
    )

    backup_timeout = SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", 1800)
    transfer_timeout = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
    mib_s = max(1, SettingsService.get_integer_setting("provisioning.backup_min_transfer_mib_s", 10))
    downloads = sum(
        size // (mib_s * 1024 * 1024) + _S3_COMPLETION_MARGIN_SECONDS for size in (base_bytes, differential_bytes)
    )
    # A push is bounded by the transfer timeout, but budgeting the worst case for both would make
    # every pair exceed the broker's visibility window: size them at the minimum transfer rate.
    pushes = sum(
        min(transfer_timeout, size // (mib_s * 1024 * 1024) + _S3_COMPLETION_MARGIN_SECONDS) + _SSH_SETUP_MARGIN_SECONDS
        for size in (base_bytes, differential_bytes)
    )
    node_step = 2 * backup_timeout + PAIR_LOCK_WAIT_SECONDS + PAIR_NODE_MARGIN_SECONDS + _SSH_SETUP_MARGIN_SECONDS
    return backup_task_timeout(estimated_bytes) + downloads + pushes + node_step + PAIR_VERIFY_MARGIN_SECONDS


# ---------------------------------------------------------------------------- node step


def run_pair_step(
    server: VirtualminServer, variables: dict[str, Any], *, token: str, domain_id: str, timeout_seconds: int
) -> Result[PairStepResult, str]:
    """Run virtualmin_pair_restore.yml once; every non-conclusive outcome is UNKNOWN."""
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

    if (
        not is_chain_domain(variables.get("chain_domain"))
        or re.fullmatch(CHAIN_DOMAIN_ID_PATTERN, str(variables.get("chain_domain_id", ""))) is None
        or re.fullmatch(CHAIN_RUN_ID_PATTERN, str(variables.get("chain_token", ""))) is None
    ):
        return Err("The pair step inputs are not acceptable to the node", retriability=Retriability.NOT_RETRIABLE)
    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err(
            f"Server {server.hostname} is manually registered (no managed node_deployment); pair restore is unavailable",
            retriability=Retriability.NOT_RETRIABLE,
        )
    result = AnsibleService().run_playbook(deployment, PAIR_PLAYBOOK, variables, timeout_seconds=timeout_seconds)
    if result.is_err():
        return Err(f"Pair step could not run: {result.unwrap_err()}", retriability=Retriability.UNKNOWN)
    run = result.unwrap()
    if not run.success:
        return Err(
            f"Pair step playbook failed or timed out (rc={run.return_code}); node state is uncertain",
            retriability=Retriability.UNKNOWN,
        )
    return parse_pair_step_result(
        run.stdout, token=token, domain_id=domain_id, action=str(variables.get("pair_action", "restore"))
    )


# ---------------------------------------------------------------------------- workflow


def _superseded() -> Err[str]:
    return Err("Restore execution superseded; no destructive work performed", retriability=Retriability.NOT_RETRIABLE)


def restore_pair(  # noqa: C901, PLR0911, PLR0912, PLR0913, PLR0915  # Distinct fail-closed gates
    service: VirtualminBackupService,
    account: VirtualminAccount,
    config: RestoreConfig,
    target_server: VirtualminServer,
    restore_id: str,
    note_sink: Callable[[dict[str, Any]], int] | None,
) -> Result[dict[str, Any], str]:
    """The pair restore workflow (see the module docstring). Never raises for an expected failure."""
    from .spool import release_spool_reservation, renew_spool_reservation  # noqa: PLC0415
    from .virtualmin_backup_service import (  # noqa: PLC0415  # Circular
        CHAIN_ROLE_STANDALONE,
        BackupConfig,
        VirtualminBackupService,
    )

    if not (config.restore_email and config.restore_databases and config.restore_files and config.restore_ssl):
        return Err("A pair restore restores every component", retriability=Retriability.NOT_RETRIABLE)
    token = config.pair_token
    if re.fullmatch(CHAIN_RUN_ID_PATTERN, token) is None:
        return Err("The pair restore job carries no run token", retriability=Retriability.NOT_RETRIABLE)
    transfer_timeout = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
    lease = transfer_timeout + 600

    held: list[tuple[str, str]] = []  # (spool path, archive name)
    pushed: list[str] = []
    determinate = False
    succeeded = False
    prior_status = ""
    status_changed = False
    try:
        # ---- preflight: download BOTH archives, verify checksums, verify exact lineage ----------
        service._update_restore_progress(restore_id, "downloading", 10)
        manifests: dict[str, dict[str, Any]] = {}
        for label, backup_id in (("base", config.backup_id), ("differential", config.differential_backup_id)):
            download = service._download_backup_to_spool(backup_id)
            if download.is_err():
                return Err(download.unwrap_err(), retriability=retriability_of(download))
            path, manifest = download.unwrap()
            held.append((path, str(manifest["archive_name"])))
            manifests[label] = manifest
        refusal = pair_lineage_refusal(
            manifests["base"], manifests["differential"], service_id=account.service_id, domain=account.domain
        )
        if refusal is not None:
            return Err(refusal, retriability=Retriability.NOT_RETRIABLE)
        domain_id = str(manifests["base"].get("virtualmin_domain_id"))

        # ---- the target must be the live domain this pair belongs to ------------------------------
        service._update_restore_progress(restore_id, "verifying_target", 25)
        gate = service._target_domain_gate(target_server, account, force=config.force_restore)
        if gate.is_err():
            return Err(gate.unwrap_err(), retriability=retriability_of(gate))
        if not gate.unwrap():
            return Err(
                "A pair restore needs the live domain; restore the base alone to recreate a missing domain",
                retriability=Retriability.NOT_RETRIABLE,
            )

        # ---- one standalone safety backup of the target -------------------------------------------
        service._update_restore_progress(restore_id, "safety_backup", 35)
        safety = VirtualminBackupService(target_server).backup_domain(
            account=account,
            config=BackupConfig(chain_role=CHAIN_ROLE_STANDALONE),
            ownership=getattr(service, "_ownership", None),
        )
        if safety.is_err():
            return Err(
                f"Pre-restore safety backup failed: {safety.unwrap_err()}", retriability=Retriability.NOT_RETRIABLE
            )
        safety_id = str(safety.unwrap().get("backup_id", ""))
        if note_sink is not None and note_sink({"safety_backup_id": safety_id}) == 0:
            return Err(
                "Restore execution superseded; the safety backup was not recorded",
                retriability=Retriability.NOT_RETRIABLE,
            )

        # ---- push both archives; the leases of what is still held are renewed at every stage -----
        for label in ("base", "differential"):
            if not service._owns_execution():
                return _superseded()
            for _path, name in held:
                renew_spool_reservation(name, lease)
            service._update_restore_progress(restore_id, f"pushing_{label}", 55 if label == "base" else 62)
            manifest = manifests[label]
            push = service._push_archive_to_target(
                target_server, str(manifest["archive_name"]), str(manifest["checksum_sha256"])
            )
            if push.is_err():
                determinate = True  # nothing destructive was issued
                return Err(push.unwrap_err(), retriability=retriability_of(push))
            pushed.append(str(manifest["archive_name"]))

        # ---- last gates before anything destructive ------------------------------------------------
        regate = service._target_domain_gate(target_server, account, force=config.force_restore)
        if regate.is_err() or not regate.unwrap():
            determinate = True
            return Err(
                f"Pre-restore re-check failed: {regate.unwrap_err() if regate.is_err() else 'domain missing'}",
                retriability=Retriability.NOT_RETRIABLE,
            )
        if not service._owns_execution():
            determinate = True
            return _superseded()
        if (
            note_sink is not None
            and note_sink(
                {
                    "pair_node_step": "dispatching",
                    "virtualmin_domain_id": domain_id,
                    "pair_archives": [manifests["base"]["archive_name"], manifests["differential"]["archive_name"]],
                }
            )
            == 0
        ):
            determinate = True
            return _superseded()

        # PRAHO's view of the account: suspended for the duration, so reconcile - the only thing
        # allowed to enable it again - re-enables it after a verified restore (ADR-0051).
        prior_status = account.status
        VirtualminAccount.objects.filter(pk=account.pk).update(  # fsm-bypass: CharField account status
            status="suspended", status_message="Pair restore in progress", updated_at=timezone.now()
        )
        status_changed = True

        # ---- ONE locked node execution --------------------------------------------------------------
        service._update_restore_progress(restore_id, "restoring", 70)
        variables = {
            "pair_action": "restore",
            "chain_domain": account.domain,
            "chain_domain_id": domain_id,
            "chain_token": token,
            "pair_lock_wait_seconds": PAIR_LOCK_WAIT_SECONDS,
            "pair_step_hold_seconds": config.pair_step_hold_seconds,
            "pair_base_archive": manifests["base"]["archive_name"],
            "pair_diff_archive": manifests["differential"]["archive_name"],
            "pair_base_sha": manifests["base"]["checksum_sha256"],
            "pair_diff_sha": manifests["differential"]["checksum_sha256"],
        }
        timeout = (
            2 * service._backup_command_timeout()
            + PAIR_LOCK_WAIT_SECONDS
            + PAIR_NODE_MARGIN_SECONDS
            + variables["pair_step_hold_seconds"]
        )
        outcome = run_pair_step(target_server, variables, token=token, domain_id=domain_id, timeout_seconds=timeout)
        if outcome.is_err():
            return Err(outcome.unwrap_err(), retriability=retriability_of(outcome))
        step = outcome.unwrap()
        checkpoints = step.checkpoint_dicts()
        if note_sink is not None:
            note_sink({"pair_checkpoints": checkpoints, "pair_node_step": step.outcome})
        if step.outcome == "refused" and not step.ran:
            determinate = True  # the node is as it was: reconcile has nothing to undo
            return Err(f"Pair restore refused by the node: {step.reason}", retriability=Retriability.NOT_RETRIABLE)
        if step.outcome != "ok":
            return Err(
                f"Pair restore stopped on the node ({step.reason}); the domain stays disabled behind the "
                "maintenance page until an operator resolves it",
                retriability=Retriability.UNKNOWN,
            )
        broken = step.barrier_broken()
        if broken is not None:
            return Err(f"Pair restore reported success but {broken}", retriability=Retriability.UNKNOWN)

        # ---- verification ------------------------------------------------------------------------------
        service._update_restore_progress(restore_id, "verifying", 90)
        verify = service._verify_restored_domain(target_server, account)
        if verify.is_err():
            return Err(
                f"Pair restore finished but could not be verified: {verify.unwrap_err()}",
                retriability=Retriability.UNKNOWN,
            )
        expected_features = manifests["differential"].get("domain_features")
        live_features = service._domain_features(account)
        if (
            isinstance(expected_features, list)
            and live_features is not None
            and set(live_features) != set(expected_features)
        ):
            return Err(
                "Pair restore finished but the domain's features differ from the backup's",
                retriability=Retriability.UNKNOWN,
            )
        determinate = True
        succeeded = True
        service._update_restore_progress(restore_id, "completed", 100)
        return Ok(
            {
                "restore_id": restore_id,
                "restore_mode": RESTORE_MODE_PAIR,
                "base_backup_id": config.backup_id,
                "differential_backup_id": config.differential_backup_id,
                "safety_backup_id": safety_id,
                "domain": account.domain,
                "pair_checkpoints": checkpoints,
                "completed_at": timezone.now().isoformat(),
            }
        )
    finally:
        for path, name in held:
            try:
                from pathlib import Path  # noqa: PLC0415

                Path(path).unlink(missing_ok=True)
            except OSError:
                logger.warning("⚠️ [PairRestore] Spool cleanup failed for %s", path)
            release_spool_reservation(name)
        if determinate:
            for name in pushed:
                service._cleanup_remote_archive(target_server, name)
            # The node is as it was (a refusal, or a refusal before the barrier): hand the account
            # back as it was. After a verified success it stays suspended for reconcile to enable.
            if status_changed and prior_status and not succeeded:
                VirtualminAccount.objects.filter(
                    pk=account.pk, status="suspended"
                ).update(  # fsm-bypass: CharField account status
                    status=prior_status, status_message="", updated_at=timezone.now()
                )


def resolve_pair_job(job: VirtualminProvisioningJob, *, resolved_by: str, note: str) -> Result[bool, str]:
    """Operator resolution of a pair restore parked in attention.

    The node is asked to release the pair: under the per-domain lock it writes the job's cancel
    marker (a late invocation can never start), takes the maintenance host down and leaves the
    domain disabled. Only when that is confirmed is the job failed and the account released; the
    account stays suspended in PRAHO's view, so reconcile enables the domain again (ADR-0051)
    when its service is active. A job that never reached the node needs no release.
    """
    from .virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415  # Circular

    if job.account_id is None or job.account is None:
        return Err("The job has no account")
    parameters = job.parameters or {}
    domain_id = str(parameters.get("virtualmin_domain_id", ""))
    token = str(parameters.get("pair_token", ""))
    if domain_id and token and parameters.get("pair_node_step"):
        released = run_pair_step(
            job.server,
            {
                "pair_action": "release",
                "chain_domain": job.account.domain,
                "chain_domain_id": domain_id,
                "chain_token": token,
                "pair_lock_wait_seconds": 30,
            },
            token=token,
            domain_id=domain_id,
            timeout_seconds=PAIR_NODE_MARGIN_SECONDS,
        )
        if released.is_err() or released.unwrap().outcome != "released":
            detail = released.unwrap_err() if released.is_err() else released.unwrap().reason
            return Err(f"Could not release the pair restore on the node ({detail}); the account stays held")
    with transaction.atomic():
        VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        rows = VirtualminProvisioningJob.objects.filter(
            pk=job.pk, status="attention"
        ).update(  # fsm-bypass: CharField job status; attention -> failed is the only edge
            status="failed",
            status_message=f"Manually resolved by {resolved_by}: {note}",
            next_retry_at=None,
            updated_at=timezone.now(),
        )
        if not rows:
            transaction.set_rollback(True)
            return Err("Only a job awaiting attention can be resolved.")
    backups = VirtualminBackupService(job.server)
    for archive_name in parameters.get("pair_archives", []):
        removed = backups.remove_staged_archive(str(archive_name))
        if removed.is_err():
            logger.warning("⚠️ [PairRestore] Staged archive %s not removed: %s", archive_name, removed.unwrap_err())
    from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415  # Circular

    if job.account.service_id:
        reconcile_virtualmin_service_state_async(str(job.account.service_id))
    return Ok(True)


def resolve_pair_job_node_lost(job: VirtualminProvisioningJob, *, resolved_by: str, note: str) -> Result[bool, str]:
    """Operator "node lost" for a pair restore in attention whose node can no longer be reached.

    "Confirm stopped" (``resolve_pair_job``) needs the node to lift its barrier, which a lost node
    cannot do. This path is allowed only while the job's server (the restore target) is failed or
    its deployment destroyed. In one transaction under the account lock it fails the job, ROTATES
    its execution token (a late runner that comes back can no longer finish or publish anything)
    and discards the chain. The account stays suspended in PRAHO's view and says why; reconcile
    (ADR-0051), the only writer of the enabled state, decides when it is enabled again.
    """
    if job.account_id is None:
        return Err("The job has no account")
    if not is_pair_job(job.operation, job.parameters or {}):
        return Err("Only a pair restore can be resolved as node lost here")
    with transaction.atomic():
        locked = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        server = VirtualminServer.objects.select_related("node_deployment").get(pk=job.server_id)
        refusal = node_lost_refusal(server)
        if refusal is not None:
            transaction.set_rollback(True)
            return Err(refusal)
        rows = VirtualminProvisioningJob.objects.filter(
            pk=job.pk, status="attention"
        ).update(  # fsm-bypass: CharField job status; attention -> failed is the only edge
            status="failed",
            status_message=f"Node lost; resolved by {resolved_by}: {note}",
            execution_token=uuid.uuid4(),
            next_retry_at=None,
            updated_at=timezone.now(),
        )
        if not rows:
            transaction.set_rollback(True)
            return Err("Only a job awaiting attention can be resolved.")
        invalidate_chain(locked)
        VirtualminAccount.objects.filter(
            pk=locked.pk, status="suspended"
        ).update(  # fsm-bypass: CharField account status
            status_message="The node was lost during a pair restore; the account is suspended until it is reconciled",
            updated_at=timezone.now(),
        )
    logger.warning("⚠️ [PairRestore] Node declared lost: job=%s server=%s by=%s", job.pk, job.server_id, resolved_by)
    # If the node is still reachable (a failed health check is not proof it is gone) the archives staged
    # for the restore are removed in the background; the request never waits on a node declared lost.
    if (job.parameters or {}).get("pair_archives") and not deployment_destroyed(server):
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task("apps.provisioning.virtualmin_tasks.remove_pair_job_archives", str(job.pk))
    return Ok(True)
