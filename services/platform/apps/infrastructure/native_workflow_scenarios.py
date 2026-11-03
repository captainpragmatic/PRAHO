"""Real services/jobs and native state: create, backup, raise, restore and staff lifecycle."""

from __future__ import annotations

import json
import os
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid5

from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.native_lab import ROOT, NativeAuthority, native_driver
from apps.infrastructure.native_workflow import native_fixture_actor, require_fixture_dns
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_node_policy import managed_quota_refusal
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.services import HostingAccountStaffActions
from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig, backup_storage_client
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway, listing_enabled
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
)
from apps.provisioning.virtualmin_tasks import reconcile_virtualmin_service_state
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.provisioning.service_models import Service
    from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
    from apps.users.models import User


def _require(result: Any, message: str) -> Any:
    if result.is_err():
        raise ValueError(message + "; inspect the private native job/deployment record")
    return result.unwrap()


def _owned(authority: NativeAuthority, deployment: NodeDeployment) -> None:
    native_driver().owned_server(authority.path)
    deployment.refresh_from_db()
    if deployment.external_node_id != str(authority.manifest["server_id"]):
        raise ValueError("The native deployment resource changed")
    require_fixture_dns(deployment, authority.manifest["ipv4"])


def _storage(authority: NativeAuthority) -> None:
    names = {
        "backup.s3_endpoint_url": "PRAHO_NATIVE_S3_ENDPOINT_URL",
        "backup.s3_bucket_name": "PRAHO_NATIVE_S3_BUCKET",
        "backup.aws_access_key_id": "PRAHO_NATIVE_S3_ACCESS_KEY_ID",
        "backup.aws_secret_access_key": "PRAHO_NATIVE_S3_SECRET_ACCESS_KEY",
    }
    values = {key: os.environ.get(variable, "") for key, variable in names.items()}
    if not all(values.values()) or values["backup.s3_bucket_name"] != "praho-native-" + authority.manifest["run"]:
        raise ValueError("An approved isolated S3 fixture and exact praho-native-<run UUID> bucket are required")
    for key, value in values.items():
        _require(SettingsService.update_setting(key, value), "Native fixture storage configuration refused")
    backup_storage_client().head_bucket(Bucket=values["backup.s3_bucket_name"])


def _marker(authority: NativeAuthority, account: VirtualminAccount, action: str, value: str = "") -> str:
    driver = native_driver()
    connection = driver.ssh(authority.path)
    try:
        sftp = connection.open_sftp()
        sftp.put(str(ROOT / "tests/virtualmin_lab/native/lifecycle_probe.py"), "/root/praho-native-lifecycle-probe.py")
        sftp.chmod("/root/praho-native-lifecycle-probe.py", 0o700)
        sftp.close()
    finally:
        connection.close()
    response = json.loads(
        driver.remote(
            authority.path,
            "/usr/bin/python3 /root/praho-native-lifecycle-probe.py",
            payload=json.dumps(
                {
                    "run": authority.manifest["run"],
                    "username": account.virtualmin_username,
                    "action": action,
                    "value": value,
                }
            ),
        )
    )
    if not response.get("uid") or not response.get("gid"):
        raise ValueError("The marker was not observed through an independent native tenant identity")
    return str(response["value"])


def _verified(service: Service, allowance: int) -> None:
    from apps.provisioning.hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    limits = ServiceHostingLimits.objects.get(service=service)
    account = VirtualminAccount.objects.get(service=service)
    if (
        not account.quota_managed
        or limits.applied_revision != limits.revision
        or limits.operational_revision != limits.revision
        or limits.verified_at is None
        or limits.applied_disk_allowance_mib != allowance
        or not limits.verified_receipt
    ):
        raise ValueError("The real public workflow has no verified current purchased allowance")


def _node_enabled(account: VirtualminAccount) -> bool:
    response = _require(
        VirtualminGateway(VirtualminConfig(server=account.server)).call(
            "list-domains",
            {"domain": account.domain, "multiline": ""},
        ),
        "Native domain read failed",
    )
    rows = response.data.get("data") if response.success else None
    if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("name") != account.domain:
        raise ValueError("The native account domain identity is missing or ambiguous")
    value = listing_enabled(rows[0].get("values", {}))
    if value is None:
        raise ValueError("The native enabled state is unknown")
    return value


def _adopt_node(authority: NativeAuthority, deployment: NodeDeployment) -> tuple[VirtualminServer, User]:
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    run = UUID(authority.manifest["run"])
    actor = native_fixture_actor(run)
    server_id = deployment.virtualmin_server_id
    if server_id is None:
        raise ValueError("The public deployment has no registered native server")
    server = VirtualminServer.objects.get(pk=server_id)
    inspected = review_node_hosting(str(server.pk), str(actor.pk), "inspect")
    if inspected.get("outcome") != "inspected":
        raise ValueError("Real native node inspection did not produce a review")
    adopted = review_node_hosting(
        str(server.pk),
        str(actor.pk),
        "adopt_quota",
        {
            "review_id": inspected["review_id"],
            "reason": "Adopt only this disposable native acceptance VM",
        },
    )
    if adopted.get("outcome") != "verified" or managed_quota_refusal(server):
        raise ValueError("Real native quota adoption did not verify this node")
    return server, actor


def _fixture_account(
    authority: NativeAuthority,
    deployment: NodeDeployment,
    server: VirtualminServer,
) -> tuple[Service, VirtualminAccount]:
    from apps.billing.models import Currency  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.provisioning.service_models import Service, ServicePlan  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    run = UUID(authority.manifest["run"])
    customer, _ = Customer.objects.get_or_create(
        name="Native quota acceptance " + str(run),
        defaults={
            "company_name": "Native quota acceptance",
            "customer_type": "company",
            "status": "active",
            "primary_email": "native-customer@example.invalid",
        },
    )
    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    initial, _ = ServicePlan.objects.get_or_create(
        name="Native five " + str(run),
        defaults={
            "plan_type": "shared_hosting",
            "price_monthly": Decimal("7.31"),
            "disk_space_gb": 5,
            "bandwidth_gb": 20,
        },
    )
    domain, username = "native-" + run.hex[:12] + ".example.com", "nat" + run.hex[:10]
    service = Service.objects.filter(customer=customer, username=username).first()
    if service is None:
        service = Service.objects.create(
            customer=customer,
            service_plan=initial,
            currency=currency,
            service_name=domain,
            domain=domain,
            username=username,
            status="active",
            price=Decimal("7.31"),
        )
        # The customer snapshot was already captured. Late catalog edits must not
        # change the actual create-domain command or verified purchased allowance.
        initial.disk_space_gb = 90
        initial.save(update_fields=["disk_space_gb"])
    account = VirtualminAccount.objects.filter(service=service).first()
    if account is None:
        _owned(authority, deployment)
        account = _require(
            VirtualminProvisioningService(server).create_virtualmin_account(
                VirtualminAccountCreationData(service=service, domain=domain, username=username, server=server),
            ),
            "Public native account creation refused",
        )
    if account.server_id != server.pk or account.domain != domain or account.virtualmin_username != username:
        raise ValueError("The native fixture account ownership changed")
    return service, account


def _take_backup(
    authority: NativeAuthority,
    deployment: NodeDeployment,
    service: Service,
    account: VirtualminAccount,
) -> dict[str, Any]:
    run = UUID(authority.manifest["run"])
    state = dict(authority.manifest.get("platform_workflow", {}))
    if not state.get("backup_id"):
        _verified(service, 5120)
        _marker(authority, account, "write", "before-" + str(run))
        _owned(authority, deployment)
        backup = _require(
            VirtualminBackupManagementService(account.server).create_backup_job(
                account,
                BackupConfig(include_email=False),
                initiated_by="native-" + str(run),
                execute_inline=True,
            ),
            "Public native backup admission refused",
        )
        backup.refresh_from_db()
        if backup.status != "completed" or not backup.result.get("backup_id"):
            raise ValueError("Real native backup did not complete")
        state["backup_id"] = backup.result["backup_id"]
        authority.manifest["platform_workflow"] = state
        native_driver().write_manifest(authority.path, authority.manifest)
    return state


def _raise_resources(  # noqa: PLR0913 -- Explicit owned scenario context.
    authority: NativeAuthority,
    deployment: NodeDeployment,
    service: Service,
    account: VirtualminAccount,
    actor: User,
    state: dict[str, Any],
) -> None:
    from apps.provisioning.service_models import ServicePlan  # noqa: PLC0415
    from apps.tickets.models import Ticket  # noqa: PLC0415

    run = UUID(authority.manifest["run"])
    target, _ = ServicePlan.objects.get_or_create(
        name="Native ten " + str(run),
        defaults={
            "plan_type": "shared_hosting",
            "price_monthly": Decimal("99"),
            "disk_space_gb": 10,
            "bandwidth_gb": 20,
        },
    )
    ticket, _ = Ticket.objects.get_or_create(
        customer=service.customer,
        title="Native resource-only exception " + str(run),
        defaults={"description": "Explicit resource change; billing stays unchanged"},
    )
    if not state.get("raised"):
        _owned(authority, deployment)
        service.refresh_from_db()
        application = grant_resource_override(
            user=actor,
            service=service,
            target_plan_id=target.pk,
            ticket_id=ticket.pk,
            reason="Disposable native acceptance resource-only change",
            expected_revision=1,
            submission_id=uuid5(run, "resource-raise"),
            billing_unchanged=True,
        )
        if apply_hosting_limits(application.pk) != "completed":
            raise ValueError("Real native quota change did not verify")
        _verified(service, 10240)
        state["raised"] = True
        authority.manifest["platform_workflow"] = state
        native_driver().write_manifest(authority.path, authority.manifest)


def _restore_and_lifecycle(
    authority: NativeAuthority,
    deployment: NodeDeployment,
    service: Service,
    account: VirtualminAccount,
    state: dict[str, Any],
) -> None:
    run = UUID(authority.manifest["run"])
    _marker(authority, account, "write", "after-" + str(run))
    _owned(authority, deployment)
    restore = _require(
        VirtualminBackupManagementService(account.server).create_restore_job(
            account,
            RestoreConfig(backup_id=state["backup_id"], force_restore=True),
            initiated_by="native-" + str(run),
            execute_inline=True,
        ),
        "Public native restore admission refused",
    )
    restore.refresh_from_db()
    if restore.status != "completed" or _marker(authority, account, "read") != "before-" + str(run):
        raise ValueError("Real native restore did not restore the tenant marker")
    _verified(service, 10240)
    _owned(authority, deployment)
    _require(HostingAccountStaffActions.suspend(account), "Staff suspension refused")
    reconcile_virtualmin_service_state(str(service.pk))
    account.refresh_from_db()
    if account.status != "suspended" or _node_enabled(account):
        raise ValueError("The public staff suspension did not reach the native account")
    _owned(authority, deployment)
    _require(HostingAccountStaffActions.activate(account), "Staff activation refused")
    reconcile_virtualmin_service_state(str(service.pk))
    account.refresh_from_db()
    service.refresh_from_db()
    if account.status != "active" or not _node_enabled(account) or service.price != Decimal("7.31"):
        raise ValueError("The native lifecycle changed saved billing or did not restore service")
    _verified(service, 10240)
    state.update(
        {
            "create": True,
            "catalog_pin": True,
            "restore_current_policy": True,
            "staff_lifecycle": True,
            "resource_only_billing": True,
            "fresh_deploy_dns": False,
        }
    )
    authority.manifest["platform_workflow"] = state
    native_driver().write_manifest(authority.path, authority.manifest)


def exercise_public_lifecycle(authority: NativeAuthority, deployment: NodeDeployment) -> None:
    """One exact owned VM and real storage. Missing prerequisites fail, never skip."""
    if authority.manifest.get("phase") != "verified":
        raise ValueError("Run real Ubuntu quota/reboot/update acceptance before Platform lifecycle proof")
    _owned(authority, deployment)
    _storage(authority)
    server, actor = _adopt_node(authority, deployment)
    service, account = _fixture_account(authority, deployment, server)
    state = _take_backup(authority, deployment, service, account)
    _raise_resources(authority, deployment, service, account, actor, state)
    _restore_and_lifecycle(authority, deployment, service, account, state)
