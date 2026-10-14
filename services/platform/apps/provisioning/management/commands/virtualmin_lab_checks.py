"""Lab checks for provisioning and backup contracts, through PRAHO's real code paths.

Run by `make test-virtualmin-lab` after the round trip, on node vm-b, so it
never touches the round-trip domain on vm-a. Each check fails the command:

1. create-domain on 8.x (provisioning): an absent domain probes as absent;
   `create_virtualmin_account` creates the server with the "Default Settings"
   template, the default feature set and the recovery seed as its description;
   a create retry after the server vanished re-creates it, and a second retry
   converges without creating.
2. Differential base kept: with a base established by a plain full backup, the
   ordinary full backup, the config-only backup and the migration backup
   parameters leave the base snapshot byte-identical. (The pre-restore safety
   backup runs the same standalone dispatch as the full backup; the restore
   after it deletes the base anyway, contract Q8.)
3. Private staging: archives and their .dom/.info sidecars land in a
   root-owned 0700 directory that an unprivileged user cannot read; a
   verified fetch leaves nothing behind; a staging directory others can read
   makes the fetch refuse and the archive is cleaned up.
4. Node backup (virtualmin_backup.yml, applied twice): exactly one enabled,
   non-differential schedule and no legacy one; Webmin cron runs it; running
   it as cron does writes a non-empty archive and keeps the differential base.
5. Node deploy (virtualmin.yml post-install tasks on an installed node): the
   play succeeds, and the API user it creates authenticates, can disable and
   enable a domain, lists the templates, and runs PRAHO's own backup (with
   mkdir, which only a master administrator may) and restore parameters. (A from-scratch install on praho-debian-node is the
   nightly drill, not part of this gate.)
"""

from __future__ import annotations

import io
import logging
import re
import uuid
from decimal import Decimal
from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.management.commands._virtualmin_lab import (
    LabNode,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)
from apps.provisioning.management.commands.virtualmin_lab_roundtrip import node_exec

logger = logging.getLogger(__name__)

CHECK_DOMAIN = "labcheck.praho.test"
CHECK_USER = "labcheck"
_ARCHIVE_RE = re.compile(r"^virtualmin_backup_[0-9a-f]{32}\.tar\.gz(\.dom|\.info)?$")


class Command(BaseCommand):
    help = "Provisioning and backup contract checks on lab node vm-b (lab only)"

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        state = load_state()
        node = state.node("vm-b")
        server = VirtualminServer.objects.get(hostname=node.server_hostname)
        with lab_transport(state):
            self._reset(server)
            account = self._check_create_domain(server, node)
            try:
                base = self._check_differential_base_and_staging(account, node)
                self._check_node_backup_playbook(server, node, base)
                self._check_node_deploy_playbook(server)
            finally:
                self._reset(server)
        self.stdout.write(self.style.SUCCESS("Lab checks OK"))

    # ------------------------------------------------------------- helpers

    def _gateway(self, server: Any) -> Any:
        from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415

        return VirtualminGateway(VirtualminConfig(server=server))

    def _ok(self, label: str, condition: bool, detail: object = "") -> None:
        if not condition:
            raise CommandError(f"{label}: FAILED {detail}")
        self.stdout.write(f"  ok  {label}")

    def _reset(self, server: Any) -> None:
        """Remove the check domain from vm-b and from the lab database."""
        from apps.provisioning.models import Service  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob  # noqa: PLC0415

        gateway = self._gateway(server)
        listing = gateway.list_domains_with_owners()
        if listing.is_err():
            raise CommandError(f"Cannot list vm-b domains: {listing.unwrap_err()}")
        if any(row["domain"] == CHECK_DOMAIN for row in listing.unwrap()):
            deleted = gateway.call("delete-domain", {"domain": CHECK_DOMAIN}, timeout_seconds=600)
            if deleted.is_err() or not deleted.unwrap().success:
                raise CommandError(f"Could not delete {CHECK_DOMAIN}: {deleted}")
        VirtualminProvisioningJob.objects.filter(account__domain=CHECK_DOMAIN).delete()
        VirtualminAccount.objects.filter(domain=CHECK_DOMAIN).delete()
        Service.objects.filter(domain=CHECK_DOMAIN).delete()

    def _service(self) -> Any:
        from apps.billing.models import Currency  # noqa: PLC0415
        from apps.customers.models import Customer  # noqa: PLC0415
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        customer = Customer.objects.get(primary_email="lab@praho.test")
        plan = ServicePlan.objects.get(name="Virtualmin lab hosting")
        currency = Currency.objects.get(code="RON")
        return Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name=CHECK_DOMAIN,
            domain=CHECK_DOMAIN,
            username=CHECK_USER,
            billing_cycle="monthly",
            price=Decimal("0.00"),
            status="active",
        )

    @staticmethod
    def _file_state(node: LabNode, path: str) -> str:
        return node_exec(
            node.container,
            "sh",
            "-c",
            'if [ -e "$1" ]; then printf "%s %s" "$(sha256sum < "$1" | cut -c1-16)" "$(stat -c %y "$1")"; '
            "else printf absent; fi",
            "sh",
            path,
        ).strip()

    @staticmethod
    def _staged(node: LabNode) -> list[str]:
        from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR  # noqa: PLC0415

        listing = node_exec(node.container, "sh", "-c", 'ls -1A "$1" 2>/dev/null || true', "sh", REMOTE_ARCHIVE_DIR)
        return [name for name in listing.split() if _ARCHIVE_RE.match(name) or name.startswith("labcheck_")]

    # ------------------------------------------------------------- check 1

    def _check_create_domain(self, server: Any, node: LabNode) -> Any:
        from apps.provisioning.virtualmin_gateway import listing_attribute  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415
        from apps.provisioning.virtualmin_service import (  # noqa: PLC0415
            VirtualminAccountCreationData,
            VirtualminProvisioningService,
        )

        self.stdout.write("Check 1: create-domain on Virtualmin 8.x through the provisioning service")
        gateway = self._gateway(server)
        owner = gateway.get_domain_owner(CHECK_DOMAIN)
        self._ok("an absent domain probes as absent (owner)", owner.is_ok() and owner.unwrap() is None, owner)
        state = gateway.get_domain_state(CHECK_DOMAIN)
        self._ok("an absent domain probes as absent (state)", state.is_ok() and not state.unwrap()["exists"], state)

        provisioning = VirtualminProvisioningService(server)
        created = provisioning.create_virtualmin_account(
            VirtualminAccountCreationData(
                service=self._service(), domain=CHECK_DOMAIN, username=CHECK_USER, server=server
            )
        )
        self._ok("create_virtualmin_account succeeds", created.is_ok(), created)
        account = created.unwrap()
        row = gateway.call("list-domains", {"domain": CHECK_DOMAIN, "multiline": ""}).unwrap().data["data"][0]
        values = row["values"]
        self._ok("template is Default Settings", listing_attribute(values, "Template") == "Default Settings", values)
        features = set(listing_attribute(values, "Features").split())
        self._ok("default features enabled", {"unix", "dir", "web", "mysql"} <= features, features)
        description = listing_attribute(values, "Description")
        self._ok("recovery seed stored as the description", description.startswith("PRAHO="), description)

        # Create retry: the server vanished after the first create.
        deleted = gateway.call("delete-domain", {"domain": CHECK_DOMAIN}, timeout_seconds=600)
        self._ok("server removed behind PRAHO's back", deleted.is_ok() and deleted.unwrap().success, deleted)
        job = VirtualminProvisioningJob.objects.filter(account=account, operation="create_domain").latest("created_at")
        retried = provisioning._retry_create_domain(account, job)
        exists = gateway.get_domain_owner(CHECK_DOMAIN)
        self._ok(
            "create retry re-creates the absent server", retried.is_ok() and exists.unwrap() == CHECK_USER, retried
        )
        again = provisioning._retry_create_domain(account, job)
        job.refresh_from_db()
        self._ok(
            "a second retry converges without creating",
            again.is_ok() and job.result.get("recovered") == "remote domain already present",
            job.result,
        )
        account.refresh_from_db()
        return account

    # ------------------------------------------------------------- checks 2 and 3

    def _check_differential_base_and_staging(self, account: Any, node: LabNode) -> str:
        from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR  # noqa: PLC0415
        from apps.provisioning.virtualmin_migration_service import migration_backup_params  # noqa: PLC0415

        self.stdout.write("Check 2/3: differential base kept and private staging")
        gateway = self._gateway(account.server)
        domain_id = node_exec(node.container, "virtualmin", "list-domains", "--domain", CHECK_DOMAIN, "--id-only")
        base = f"/var/webmin/modules/virtual-server/incremental/{domain_id.strip()}"

        # A base, made the way only a "base" role may: a full backup without no-differential.
        base_archive = f"{REMOTE_ARCHIVE_DIR}/labcheck_base.tar.gz"
        made = gateway.call(
            "backup-domain",
            {"domain": CHECK_DOMAIN, "dest": base_archive, "all-features": "", "mkdir": ""},
            timeout_seconds=900,
        )
        self._ok("base full backup ran", made.is_ok() and made.unwrap().success, made)
        before = self._file_state(node, base)
        self._ok("a differential base exists (non-vacuous)", before != "absent", before)

        # Check 3a: the staging directory is private, whatever mode Virtualmin gives the files.
        modes = node_exec(
            node.container, "stat", "-c", "%a %U %n", REMOTE_ARCHIVE_DIR, base_archive, f"{base_archive}.dom"
        ).split("\n")
        self._ok("staging directory is root 0700", modes[0].startswith("700 root "), modes)
        unreadable = node_exec(
            node.container,
            "sh",
            "-c",
            'su -s /bin/sh nobody -c "cat \\"$1\\"" >/dev/null 2>&1 && echo readable || echo denied',
            "sh",
            f"{base_archive}.dom",
        ).strip()
        self._ok(f"an unprivileged user cannot read the .dom sidecar ({modes[2].split()[0]})", unreadable == "denied")
        node_exec(node.container, "rm", "-f", base_archive, f"{base_archive}.dom", f"{base_archive}.info")

        # Check 2: each non-base backup leaves the base byte-identical.
        for label, argv in (
            ("ordinary full backup (CLI, job layer)", ["backup", CHECK_DOMAIN]),
            ("config-only backup (CLI, job layer)", ["backup", CHECK_DOMAIN, "--type", "config_only"]),
        ):
            out = io.StringIO()
            call_command("virtualmin_backup", *argv, stdout=out)
            self._ok(f"{label} completed", "Backup ID:" in out.getvalue(), out.getvalue()[-400:])
            after = self._file_state(node, base)
            self._ok(f"{label} kept the base", after == before, f"{before} -> {after}")
            self._ok(f"{label} left nothing staged (archive and sidecars fetched or removed)", not self._staged(node))

        archive = f"migration_{uuid.uuid4()}.tar.gz"
        migrated = gateway.call(
            "backup-domain", {"domain": CHECK_DOMAIN, **migration_backup_params(archive)}, timeout_seconds=900
        )
        self._ok("migration backup parameters accepted", migrated.is_ok() and migrated.unwrap().success, migrated)
        after = self._file_state(node, base)
        self._ok("migration backup kept the base", after == before, f"{before} -> {after}")
        path = f"{REMOTE_ARCHIVE_DIR}/{archive}"
        node_exec(node.container, "rm", "-f", path, f"{path}.dom", f"{path}.info")

        # Check 3b: a staging directory others can read makes the fetch refuse.
        node_exec(node.container, "chmod", "0755", REMOTE_ARCHIVE_DIR)
        try:
            refused = ""
            try:
                call_command("virtualmin_backup", "backup", CHECK_DOMAIN, stdout=io.StringIO())
            except CommandError as error:
                refused = str(error)
            self._ok("fetch refuses a world-readable staging directory", "fetch failed" in refused, refused[-300:])
            self._ok("the refused archive and its sidecars were removed", not self._staged(node))
        finally:
            node_exec(node.container, "chmod", "0700", REMOTE_ARCHIVE_DIR)
        logger.info("✅ [VirtualminLab] Differential base and staging checks passed")
        return base

    # ------------------------------------------------------------- check 4

    def _run_playbook(self, server: Any, playbook: str, extra: dict[str, Any] | None = None) -> None:
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

        result = AnsibleService().run_playbook(server.node_deployment, playbook, extra, timeout_seconds=1800)
        ok = result.is_ok() and result.unwrap().success
        detail = result.unwrap_err() if result.is_err() else result.unwrap().stdout[-1500:]
        self._ok(f"{playbook} applied through AnsibleService", ok, detail)

    def _check_node_backup_playbook(self, server: Any, node: LabNode, base: str) -> None:
        """The nightly node backup exists, runs from Webmin cron, backs up, keeps the base."""
        import json  # noqa: PLC0415

        self.stdout.write("Check 4: the node's nightly backup (virtualmin_backup.yml)")
        dest = "/var/backups/virtualmin/%Y-%m-%d"
        before = self._file_state(node, base)
        for run in (1, 2):
            self._run_playbook(server, "virtualmin_backup.yml")
            listing = json.loads(node_exec(node.container, "virtualmin", "list-scheduled-backups", "--json"))
            mine = [row for row in listing["data"] if row["values"].get("destination") == [dest]]
            self._ok(f"run {run}: exactly one schedule for {dest}", len(mine) == 1, listing["data"])
            values = mine[0]["values"]
            self._ok(
                f"run {run}: enabled, not differential",
                (values["enabled"], values["differential"]) == (["Yes"], ["No"]),
                values,
            )
            self._ok(f"run {run}: no legacy schedule left", len(listing["data"]) == 1, listing["data"])
        schedule_id = mine[0]["name"]
        cron = node_exec(
            node.container,
            "sh",
            "-c",
            'grep -l "^arg1=--id $1$" /etc/webmin/webmincron/crons/*.cron || true',
            "sh",
            schedule_id,
        ).strip()
        self._ok("Webmin cron runs the schedule", bool(cron), schedule_id)
        node_exec(node.container, "sh", "-c", "rm -rf /var/backups/virtualmin/????-??-??")
        node_exec(
            node.container,
            "sh",
            "-c",
            "cd /usr/share/webmin/virtual-server && WEBMIN_CONFIG=/etc/webmin WEBMIN_VAR=/var/webmin "
            # Webmin refuses a relative script path; this is what its cron runs.
            '/usr/share/webmin/virtual-server/backup.pl --id "$1" >/dev/null 2>&1',
            "sh",
            schedule_id,
        )
        members = node_exec(
            node.container,
            "sh",
            "-c",
            'for f in /var/backups/virtualmin/*/"$1".tar.gz; do tar -tzf "$f" | wc -l; done',
            "sh",
            CHECK_DOMAIN,
        ).split()
        self._ok("the scheduled run wrote a non-empty archive", bool(members) and int(members[0]) > 0, members)
        after = self._file_state(node, base)
        self._ok("the scheduled run kept the differential base", after == before, f"{before} -> {after}")
        node_exec(node.container, "sh", "-c", "rm -rf /var/backups/virtualmin/????-??-??")

    # ------------------------------------------------------------- check 5

    def _check_node_deploy_playbook(self, server: Any) -> None:
        """virtualmin.yml's post-install tasks succeed and its API user can provision."""
        import secrets  # noqa: PLC0415

        from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        self.stdout.write("Check 5: node deploy (virtualmin.yml) and its API user")
        user, password = "praho-labcheck", secrets.token_urlsafe(24)
        self._run_playbook(server, "virtualmin.yml", {"praho_api_user": user, "praho_api_password": password})
        as_api_user = VirtualminServer.objects.get(pk=server.pk)  # unsaved credential swap
        as_api_user.api_username = user
        as_api_user.set_api_password(password)
        gateway = VirtualminGateway(VirtualminConfig(server=as_api_user, use_credential_vault=False))
        listed = gateway.call("list-domains", {"multiline": ""})
        self._ok("the API user authenticates", listed.is_ok() and listed.unwrap().success, listed)
        for program in ("disable-domain", "enable-domain"):
            changed = gateway.call(program, {"domain": CHECK_DOMAIN}, timeout_seconds=600)
            self._ok(f"the API user can {program}", changed.is_ok() and changed.unwrap().success, changed)
        templates = gateway.list_templates()
        self._ok(
            "the API user lists the Default Settings template",
            templates.is_ok() and "Default Settings" in templates.unwrap(),
            templates,
        )
        self._check_api_user_backup_and_restore(gateway)

    def _check_api_user_backup_and_restore(self, gateway: Any) -> None:
        """PRAHO's own backup and restore parameters, sent as the deployed API user.

        `backup-domain --mkdir` is refused to non-master callers, so this also
        proves the helper's user really is a Virtualmin master administrator.
        """
        from apps.provisioning.virtualmin_backup_service import (  # noqa: PLC0415
            CHAIN_ROLE_STANDALONE,
            REMOTE_ARCHIVE_DIR,
            differential_flags,
        )

        node = load_state().node("vm-b")
        node_exec(node.container, "rm", "-rf", REMOTE_ARCHIVE_DIR)
        archive = f"{REMOTE_ARCHIVE_DIR}/virtualmin_backup_{uuid.uuid4().hex}.tar.gz"
        backed_up = gateway.call(
            "backup-domain",
            {
                "domain": CHECK_DOMAIN,
                "dest": archive,
                "all-features": "",
                "mkdir": "",
                **differential_flags(CHAIN_ROLE_STANDALONE),
            },
            timeout_seconds=900,
        )
        self._ok(
            "the API user runs PRAHO's full backup (mkdir, no-differential)",
            backed_up.is_ok() and backed_up.unwrap().success,
            backed_up,
        )
        mode = node_exec(node.container, "stat", "-c", "%a %U", REMOTE_ARCHIVE_DIR).strip()
        self._ok("mkdir created the staging directory root 0700", mode == "700 root", mode)
        restored = gateway.call(
            "restore-domain", {"domain": CHECK_DOMAIN, "source": archive, "all-features": ""}, timeout_seconds=900
        )
        self._ok(
            "the API user restores it over the live domain",
            restored.is_ok() and restored.unwrap().success,
            restored,
        )
        node_exec(node.container, "rm", "-f", archive, f"{archive}.dom", f"{archive}.info")
