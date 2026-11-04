"""The only quota network boundary; validated payloads travel over enrolled SSH."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from django.db import connection

if TYPE_CHECKING:
    from .hosting_limit_execution_models import HostingLimitExecution
    from .virtualmin_models import VirtualminServer


def run_quota_operation(server: VirtualminServer, action: str, request: dict[str, Any]) -> dict[str, Any]:
    from .hosting_node_transport import run_quota_operation as native_run  # noqa: PLC0415 -- Shared enrolled transport.

    if connection.in_atomic_block:
        raise RuntimeError("Native quota operations must run after the database transaction commits.")
    return native_run(server, action, request)


def probe_account_quota(execution: HostingLimitExecution) -> dict[str, Any]:
    from .virtualmin_gateway import (  # noqa: PLC0415 -- Native read boundary.
        VirtualminConfig,
        VirtualminGateway,
        listing_attribute,
    )

    job = execution.job
    account = job.account
    if account is None:
        raise ValueError("The quota application has no account identity.")
    result = VirtualminGateway(VirtualminConfig(server=job.server)).call(
        "list-domains",
        {"domain": account.domain, "multiline": ""},
    )
    if result.is_err() or not result.unwrap().success:
        raise RuntimeError("The native domain ownership could not be read.")
    rows = result.unwrap().data.get("data")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("The native domain identity is missing or ambiguous.")
    values = rows[0].get("values")
    if (
        rows[0].get("name") != account.domain
        or not isinstance(values, dict)
        or listing_attribute(values, "Username") != account.virtualmin_username
    ):
        raise ValueError("The native domain belongs to another Unix owner.")
    domain_id = listing_attribute(values, "ID")
    if not isinstance(domain_id, str) or re.fullmatch(r"[0-9]{1,30}", domain_id) is None:
        raise ValueError("The native domain has no exact numeric identity.")
    request = {
        # A read-only observation must report a reboot so Platform can revoke
        # historical verification. Mutation still requires the complete exact
        # observed/adopted boot in its separately admitted request.
        "identity": {
            **{key: value for key, value in execution.identity.items() if key != "boot_id"},
            "domain_id": domain_id,
            "domain": account.domain,
        },
        "token": str(job.execution_token),
        "generation": execution.account_epoch,
        "disk_limit_kib": 0,
        "bandwidth_limit_bytes": 0,
    }
    return run_quota_operation(job.server, "probe", request)
