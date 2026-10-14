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
4b. Chain step (virtualmin_chain_backup.yml, through AnsibleService): a base resets
   the snapshot to a fresh fingerprint, and a base with nothing changed still
   changes it (so a fingerprint can tell two bases apart); a differential passes
   the fingerprint check, leaves the snapshot byte-identical and archives only
   the changed files; a stale fingerprint, a cancelled token and a held lock
   each refuse before any backup runs, and a refused differential archives nothing.
5. Node deploy (virtualmin.yml post-install tasks on an installed node): the
   play succeeds, and the API user it creates authenticates, can disable and
   enable a domain, lists the templates, and runs PRAHO's own backup (with
   mkdir, which only a master administrator may) and restore parameters. (A
   from-scratch install on praho-debian-node is the nightly drill, not part
   of this gate.)
6. Access lock (ADR-0060). Platform reaches the lab nodes from the compose
   network gateway, which is the lab's whole node admin allowlist; vm-a sits
   on the same network outside it, so it stands in for "any other host":
   - the API user's credentials work from Platform and are refused from vm-a,
     on remote.cgi and on every page behind a login-form session. With vm-a
     added to the user's allow list the same calls from vm-a succeed, so the
     refusal is the lock, not the network or the password;
   - before virtualmin_harden.yml, vm-a reaches vm-b's port 10000; after it,
     it does not, while port 80 stays open and Platform still reaches both
     the API and SSH (the play runs twice).
"""

from __future__ import annotations

import io
import logging
import re
import subprocess
import time
import uuid
from decimal import Decimal
from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.management.commands._virtualmin_lab import (
    LabNode,
    container_address,
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
                self._check_chain_node_step(server, node)
                user, password, api_gateway = self._check_node_deploy_playbook(server)
                self._check_api_user_lock(node, user, password, api_gateway)
                self._check_firewall(server, node, api_gateway)
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

    # ------------------------------------------------------------- check 4b

    def _chain_step(  # noqa: PLR0913  # Mirrors the playbook's inputs
        self,
        server: Any,
        node: LabNode,
        mode: str,
        token: str,
        *,
        expected_fp: str = "",
        action: str = "run",
        lock_wait: int = 60,
    ) -> Any:
        """Run virtualmin_chain_backup.yml through AnsibleService; return the parsed result line."""
        from apps.provisioning.virtualmin_backup_service import (  # noqa: PLC0415
            VirtualminBackupService,
        )

        domain_id = node_exec(
            node.container, "virtualmin", "list-domains", "--domain", CHECK_DOMAIN, "--id-only"
        ).strip()
        variables: dict[str, Any] = {
            "chain_action": action,
            "chain_mode": mode if action == "run" else "",
            "chain_domain": CHECK_DOMAIN,
            "chain_domain_id": domain_id,
            "chain_token": token,
            "chain_lock_wait_seconds": lock_wait,
            "chain_archive": f"virtualmin_backup_{uuid.uuid4().hex}.tar.gz" if action == "run" else "",
        }
        if expected_fp:
            variables["chain_expected_fp"] = expected_fp
        outcome = VirtualminBackupService(server).run_chain_step(
            variables, token=token, mode=mode if action == "run" else "cancel", domain_id=domain_id
        )
        if outcome.is_err():
            raise CommandError(f"chain step {mode}/{action} unusable: {outcome.unwrap_err()}")
        return outcome.unwrap()

    def _check_chain_node_step(self, server: Any, node: LabNode) -> None:  # noqa: PLR0915  # One linear lab scenario
        """The locked node-side step: fresh snapshot, differential contents, and every refusal."""
        from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR  # noqa: PLC0415

        self.stdout.write("Check 4b: the chain step (virtualmin_chain_backup.yml)")
        domain_id = node_exec(
            node.container, "virtualmin", "list-domains", "--domain", CHECK_DOMAIN, "--id-only"
        ).strip()
        home = f"/home/{CHECK_USER}/public_html"

        def token() -> str:
            return str(uuid.uuid4())  # One fresh run token per step

        def write_file(name: str, content: str) -> None:
            node_exec(
                node.container,
                "sh",
                "-c",
                'printf "%s\n" "$2" > "$1" && chown "$3" "$1"',
                "sh",
                f"{home}/{name}",
                content,
                CHECK_USER,
            )

        def staged() -> list[str]:
            return self._staged(node)

        def regular_files(archive: str) -> set[str]:
            """Regular files in the archive's directory member (dirs and special entries excluded)."""
            listing = node_exec(
                node.container,
                "sh",
                "-c",
                'set -e; d=$(mktemp -d); trap \'rm -rf "$d"\' EXIT; tar -xzf "$1" -C "$d"; '
                'tar -tvf "$d"/*_dir.tar > "$d/list"; awk \'/^-/ {print $NF}\' "$d/list"',
                "sh",
                f"{REMOTE_ARCHIVE_DIR}/{archive}",
            )
            return {line.strip() for line in listing.splitlines() if line.strip()}

        def discard(*steps: Any) -> None:
            for step in steps:
                path = f"{REMOTE_ARCHIVE_DIR}/{step.archive}"
                node_exec(node.container, "rm", "-f", path, f"{path}.dom", f"{path}.info")

        write_file("chain-keep.txt", "unchanged after the base")
        write_file("chain-edit.txt", "first")
        try:
            base = self._chain_step(server, node, "base", token())
            self._ok("a base step succeeds", base.outcome == "ok" and base.ran, base)
            self._ok(
                "a base leaves a fresh snapshot (present, not the one before)",
                base.fp_after not in ("", "ABSENT", base.fp_before),
                base,
            )
            self._ok(
                "the step's fp_after is the snapshot on the node",
                base.fp_after == self._fingerprint(node, domain_id),
                base,
            )
            self._ok(
                "a base archive is complete (holds the unchanged file)",
                "./public_html/chain-keep.txt" in regular_files(base.archive),
            )

            again = self._chain_step(server, node, "base", token())
            self._ok(
                "Q9: a base with NO change still changes the snapshot hash",
                again.outcome == "ok" and again.fp_before == base.fp_after and again.fp_after != again.fp_before,
                (again.fp_before, again.fp_after),
            )
            discard(base)

            write_file("chain-edit.txt", "second")
            write_file("chain-new.txt", "new file")
            diff = self._chain_step(server, node, "differential", token(), expected_fp=again.fp_after)
            self._ok("a differential passes the fingerprint check", diff.outcome == "ok" and diff.ran, diff)
            self._ok(
                "a differential leaves the snapshot byte-identical",
                diff.fp_after == diff.fp_before == again.fp_after == self._fingerprint(node, domain_id),
                diff,
            )
            files = regular_files(diff.archive)
            self._ok(
                "a differential archive holds only the changed files",
                {"./public_html/chain-edit.txt", "./public_html/chain-new.txt"} <= files
                and "./public_html/chain-keep.txt" not in files,
                sorted(files),
            )
            self._ok(
                "a differential archive is smaller than the base archive",
                diff.size < again.size,
                (diff.size, again.size),
            )
            discard(diff, again)

            stale = self._chain_step(server, node, "differential", token(), expected_fp="ABSENT")
            self._ok(
                "a differential with a stale fingerprint is refused before any backup runs",
                (stale.outcome, stale.reason, stale.ran) == ("refused", "fingerprint_mismatch", False),
                stale,
            )
            self._ok("the refused differential archived nothing", not staged(), staged())

            cancelled = token()
            marker = self._chain_step(server, node, "base", cancelled, action="cancel")
            self._ok("a cancel writes its marker under the lock", marker.outcome == "cancelled", marker)
            refused = self._chain_step(server, node, "base", cancelled)
            self._ok(
                "a cancelled token refuses to run",
                (refused.outcome, refused.reason, refused.ran) == ("refused", "cancelled", False) and not staged(),
                refused,
            )
            fresh = self._chain_step(server, node, "base", token())
            self._ok("another token still runs", fresh.outcome == "ok", fresh)
            discard(fresh)

            held = subprocess.Popen(  # Holds the node's per-domain lock for the check
                ["docker", "exec", node.container, "flock", f"/run/praho/chain-{domain_id}.lock", "sleep", "40"],  # noqa: S607
            )
            try:
                time.sleep(3)
                busy = self._chain_step(server, node, "base", token(), lock_wait=5)
                self._ok(
                    "a step cannot start while the lock is held",
                    (busy.outcome, busy.reason, busy.ran) == ("refused", "lock_busy", False),
                    busy,
                )
            finally:
                held.terminate()
                held.wait(timeout=30)
        finally:
            node_exec(
                node.container,
                "sh",
                "-c",
                'rm -f /run/praho/chain-"$1".* "$2"/virtualmin_backup_*',
                "sh",
                domain_id,
                REMOTE_ARCHIVE_DIR,
            )
            node_exec(
                node.container, "rm", "-f", f"{home}/chain-keep.txt", f"{home}/chain-edit.txt", f"{home}/chain-new.txt"
            )
        logger.info("✅ [VirtualminLab] Chain step checks passed")

    def _fingerprint(self, node: LabNode, domain_id: str) -> str:
        """The node's snapshot fingerprint, computed independently of the step's script."""
        return node_exec(
            node.container,
            "sh",
            "-c",
            'f=/var/webmin/modules/virtual-server/incremental/"$1"; if [ -f "$f" ]; '
            'then printf "%s:%s" "$(sha256sum < "$f" | cut -d" " -f1)" "$(stat -c %s "$f")"; else printf ABSENT; fi',
            "sh",
            domain_id,
        ).strip()

    # ------------------------------------------------------------- check 5

    def _check_node_deploy_playbook(self, server: Any) -> tuple[str, str, Any]:
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
        return user, password, gateway

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

    # ------------------------------------------------------------- check 6

    @staticmethod
    def _docker(*argv: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # Fixed argv against local lab containers
            ["docker", *argv],  # noqa: S607  # docker from PATH, dev-only command
            input=stdin,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def _probe_from_vm_a(self, node: LabNode, user: str, password: str) -> str:
        """remote.cgi, then a login-form session, as `user` from vm-a to vm-b.

        Returns "api=<status> session=<yes|no> page=<status>". Webmin answers a
        login from a refused address with a session, then refuses every page
        behind it, so the page status is what proves the lock.
        """
        target = f"https://{container_address(node.container)}:10000"
        result = self._docker("exec", "vmlab-a", "bash", "-c", _LOCK_PROBE, "lock-probe", user, password, target)
        if result.returncode != 0:
            raise CommandError(f"lock probe from vm-a failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def _set_user_allow(self, node: LabNode, user: str, password: str, networks: list[str]) -> None:
        """Re-run the deployed helper on the node with another allow list."""
        result = self._docker(
            "exec",
            "-i",
            node.container,
            "/usr/local/sbin/praho-webmin-api-user",
            user,
            *networks,
            stdin=password + "\n",
        )
        if result.returncode != 0:
            raise CommandError(f"praho-webmin-api-user failed: {result.stderr.strip()}")

    def _check_api_user_lock(self, node: LabNode, user: str, password: str, gateway: Any) -> None:
        self.stdout.write("Check 6a: the API user logs in only from the node admin allowlist")
        # No firewall during this check (a previous run's harden play leaves one),
        # so what refuses vm-a here can only be the per-user lock. Check 6b
        # applies the firewall again.
        node_exec(node.container, "sh", "-c", "if command -v ufw >/dev/null; then ufw --force disable; fi")
        platform = container_address("vmlab-a", "Gateway")
        other = container_address("vmlab-a")
        listed = gateway.call("list-domains", {"multiline": ""})
        self._ok(f"from Platform ({platform}) remote.cgi works", listed.is_ok() and listed.unwrap().success, listed)
        refused = self._probe_from_vm_a(node, user, password)
        self._ok(
            f"from vm-a ({other}) remote.cgi and every page are refused",
            refused.startswith("api=403") and refused.endswith("page=403"),
            refused,
        )
        self._set_user_allow(node, user, password, [f"{platform}/32", f"{other}/32"])
        try:
            allowed = self._probe_from_vm_a(node, user, password)
            self._ok(
                "with vm-a on the user's allow list the same calls succeed",
                allowed == "api=200 session=yes page=200",
                allowed,
            )
        finally:
            self._set_user_allow(node, user, password, [f"{platform}/32"])
        again = self._probe_from_vm_a(node, user, password)
        self._ok("taken off again, vm-a is refused again", again.startswith("api=403"), again)

    def _check_firewall(self, server: Any, node: LabNode, gateway: Any) -> None:
        self.stdout.write("Check 6b: SSH and Webmin open only to the allowlist (virtualmin_harden.yml)")
        address = container_address(node.container)

        def reach(port: int, scheme: str) -> str:
            result = self._docker(
                "exec",
                "vmlab-a",
                "curl",
                "-sk",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"{scheme}://{address}:{port}/",
            )
            return result.stdout.strip() or "000"

        # Baseline without a firewall, so the refusal below is the play's doing.
        node_exec(node.container, "sh", "-c", "if command -v ufw >/dev/null; then ufw --force disable; fi")
        before = reach(10000, "https")
        self._ok("before the play, vm-a reaches vm-b:10000", before != "000", before)
        for run in (1, 2):
            # The play itself runs over SSH from Platform: a second run proves
            # port 22 is still open to Platform after the first.
            self._run_playbook(server, "virtualmin_harden.yml")
            self.stdout.write(f"    harden run {run} done")
        after = reach(10000, "https")
        self._ok("after the play, vm-a cannot reach vm-b:10000", after == "000", after)
        web = reach(80, "http")
        self._ok("port 80 stays open to vm-a", web == "200", web)
        listed = gateway.call("list-domains", {"multiline": ""})
        self._ok("Platform still reaches the API", listed.is_ok() and listed.unwrap().success, listed)


_LOCK_PROBE = r"""
set -uo pipefail
user="$1"; pass="$2"; target="$3"
jar="$(mktemp)"
trap 'rm -f "${jar}"' EXIT
api="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -u "${user}:${pass}" \
  "${target}/virtual-server/remote.cgi?program=list-domains&json=1")"
curl -sk --max-time 10 -o /dev/null -c "${jar}" -b 'testing=1' \
  --data-urlencode "user=${user}" --data-urlencode "pass=${pass}" "${target}/session_login.cgi"
if grep -q $'\tsid\t' "${jar}"; then session=yes; else session=no; fi
page="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -b "${jar}" "${target}/sysinfo.cgi")"
echo "api=${api} session=${session} page=${page}"
"""
