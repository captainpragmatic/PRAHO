"""A node that stops answering: the gateway times out, and PRAHO must decide what that means.

`docker pause` freezes the node, so every call ends in a timeout (the TLS handshake stalls, so these calls may
never leave the client at all). What they pin down is the classification: an unanswered call is an unknown
outcome, never a definite failure, and the replay rules follow from it. The case where the node did receive and
run the request is the `backup-domain` test below, and the mid-operation faults in
test_mid_operation_faults.py:

- a read-only program is replayed (it cannot hurt), up to the configured number of attempts;
- a program that changes the node is sent once (a second copy could run twice), also when the node did run it;
- a job whose command may have run is never reported done, and is not retried through the job pool either;
- a delete that may have run is parked for an operator and keeps the account's exclusion.
"""

from __future__ import annotations

import secrets
import time
import uuid
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.common.types import Retriability, retriability_of
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_STANDALONE,
    REMOTE_ARCHIVE_DIR,
    full_backup_params,
)
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import process_failed_virtualmin_jobs
from tests.virtualmin_lab.faults.harness import Chaos, count_attempts, exclusion_holds, resolve_as_operator
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

TIMEOUT_SECONDS = 3
BLOB_MB = 150
BACKUP_WAIT_SECONDS = 120
MAX_ATTEMPTS = 3  # virtualmin.max_retries, whose default applies in the lab


@pytest.fixture(autouse=True)
def short_request_timeout(bench: Bench) -> None:
    bench.set_setting("virtualmin.request_timeout_seconds", TIMEOUT_SECONDS)


def test_a_read_only_program_is_replayed_and_a_mutation_is_sent_once(bench: Bench, chaos: Chaos) -> None:
    with chaos.hosted("wffaulte.example.com") as account:
        gateway = VirtualminGateway(VirtualminConfig(server=bench.server("vm-a")))
        chaos.pause("vm-a")
        with count_attempts() as attempts:
            read = gateway.call("list-domains", {"name-only": ""}, timeout_seconds=TIMEOUT_SECONDS)
            write = gateway.call(
                "modify-domain", {"domain": account.domain, "desc": "timed out"}, timeout_seconds=TIMEOUT_SECONDS
            )
        chaos.unpause("vm-a")

        assert read.is_err() and retriability_of(read) is Retriability.UNKNOWN
        assert attempts["list-domains"] == MAX_ATTEMPTS, "a read-only program is replayed up to the attempt limit"
        assert write.is_err() and retriability_of(write) is Retriability.UNKNOWN
        assert attempts["modify-domain"] == 1, "a program that changes the node is sent exactly once"
        # Whether the node ever saw that one request is its own business (a paused node may not have completed
        # the handshake): the description is the new one or still the recovery seed provisioning wrote.
        chaos.wait_api("vm-a")
        [description] = bench.lab("vm-a").domain_values(account.domain)["description"]
        assert description == "timed out" or description.startswith("PRAHO="), description


def test_a_suspend_that_timed_out_is_not_reported_done_and_is_not_replayed(bench: Bench, chaos: Chaos) -> None:
    with chaos.hosted("wffaultf.example.com") as account:
        chaos.pause("vm-a")
        with count_attempts() as attempts:
            result = VirtualminProvisioningService(account.server).suspend_account(account, "workflow")
        chaos.unpause("vm-a")
        chaos.wait_api("vm-a")

        assert result.is_err()
        account.refresh_from_db()
        assert account.status == "active", "PRAHO does not claim a suspension it never saw"
        [job] = bench.jobs(account, "suspend_domain")
        assert job.status != "completed", (job.status, job.status_message)
        assert attempts["disable-domain"] == 1

        # The retry pool does not replay it either: by the time it runs, the Service says the account stays on.
        VirtualminProvisioningJob.objects.filter(pk=job.pk, status="failed").update(
            next_retry_at=timezone.now() - timedelta(seconds=1)
        )
        with count_attempts() as after:
            swept = process_failed_virtualmin_jobs()
            bench.run_queue()
        assert swept["success"]
        assert after["disable-domain"] == 0, "the uncertain command was not sent again"
        job.refresh_from_db()
        assert job.status != "completed"


def test_a_delete_that_timed_out_is_parked_and_never_replayed(bench: Bench, chaos: Chaos) -> None:
    with chaos.hosted("wffaultg.example.com") as account:
        DomainData(bench.lab_of(account), account).seed(secrets.token_hex(6))
        # The state delete accepts (see test_account_lifecycle): a failed provisioning's account, unprotected.
        VirtualminAccount.objects.filter(pk=account.pk).update(  # fsm-bypass: the state a failed provisioning leaves
            status="error", protected_from_deletion=False
        )
        account.refresh_from_db()
        chaos.pause("vm-a")
        with count_attempts() as attempts:
            result = VirtualminProvisioningService(account.server).delete_account(account)
        chaos.unpause("vm-a")
        chaos.wait_api("vm-a")

        assert result.is_err()
        [job] = bench.jobs(account, "delete_domain")
        assert job.status == "attention", (job.status, job.status_message)
        assert attempts["delete-domain"] == 1
        account.refresh_from_db()
        assert account.status == "error", "the account is not marked terminated on a guess"
        assert "virtualmin_provisioning_job_completed" not in bench.audit_actions(job)
        assert exclusion_holds(account), "a delete that may have run keeps the account's exclusion"

        with count_attempts() as after:
            process_failed_virtualmin_jobs()
            bench.run_queue()
        assert after["delete-domain"] == 0, "nothing retried it"
        job.refresh_from_db()
        assert job.status == "attention"

        resolve_as_operator(job, "workflow")
        assert not exclusion_holds(account)


def test_a_mutation_the_node_ran_while_the_caller_gave_up_is_not_sent_again(bench: Bench, chaos: Chaos) -> None:
    """The node received the request and ran it; PRAHO's read timeout fired first. It must not run it twice."""
    with chaos.hosted("wffaulth.example.com") as account:
        lab = bench.lab_of(account)
        DomainData(lab, account).add_blob(BLOB_MB)
        archive = f"virtualmin_backup_{uuid.uuid4().hex}.tar.gz"
        params = full_backup_params(
            domain=account.domain,
            dest=f"{REMOTE_ARCHIVE_DIR}/{archive}",
            chain_role=CHAIN_ROLE_STANDALONE,
            excluded_features=[],
        )
        gateway = VirtualminGateway(VirtualminConfig(server=bench.server("vm-a")))
        with count_attempts() as attempts:
            result = gateway.call("backup-domain", params, timeout_seconds=2)
            assert result.is_err() and retriability_of(result) is Retriability.UNKNOWN
            # The node keeps working after the caller has gone: the archive's .info is written last.
            deadline = time.monotonic() + BACKUP_WAIT_SECONDS
            while time.monotonic() < deadline and archive + ".info" not in lab.exec(
                "ls", "-1A", REMOTE_ARCHIVE_DIR
            ).split():
                time.sleep(1)
            time.sleep(3)  # long enough for a second copy to show up if one had been sent
        assert archive + ".info" in lab.exec("ls", "-1A", REMOTE_ARCHIVE_DIR).split(), "the node ran the request"
        assert attempts["backup-domain"] == 1, "a request the node may have run is sent exactly once"
        lab.exec("sh", "-c", f"rm -f {REMOTE_ARCHIVE_DIR}/virtualmin_backup_*")
