"""Run virtualmin_bridge.yml through the real bridge service: TLS, scheme, aliases and source deletion."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from django.conf import settings
from django.utils import timezone

from apps.provisioning.management.commands._virtualmin_lab import container_address, load_state
from apps.provisioning.migration_barrier import BarrierRecord, barrier_variables, run_barrier
from apps.provisioning.migration_bridge_service import (
    activate_target,
    install_bridge,
    prepare_bridge,
    remove_bridge,
    retire_target_activation_data,
    verify_bridge,
)
from apps.provisioning.migration_target_hold import (
    cleanup_held_target,
    held_pair_variables,
    restore_held_target,
    run_held_target_node,
)
from apps.provisioning.virtualmin_gateway import VirtualminConfig
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    VirtualminMigrationService,
    list_migration_domains,
    migration_backup_params,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_pair_restore import run_pair_step
from apps.settings.services import SettingsService
from tests.virtualmin_lab.contract.harness import BACKUP_TIMEOUT, Lab, RecordingGateway, assert_accepted

DOMAIN = "contractbridge.praho.test"


def _copy(source: str, target: str) -> None:
    subprocess.run(["docker", "cp", source, target], check=True, capture_output=True, timeout=60)  # noqa: S603, S607  # Local lab containers, fixed command.


class NativeMigrationAdapter:
    """Keep real production node work; only the namespace's DB checkpoint seam is local to this test."""

    def __init__(self, source: Lab, target: Lab, token: UUID) -> None:
        self.nodes = {source.server.pk: source, target.server.pk: target}
        self.token = token
        self.backup_timeout = SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", BACKUP_TIMEOUT)

    def _move(self, migration: VirtualminMigration, token: UUID, status: str, **fields: object) -> None:
        assert token == self.token
        # Production's DB lease/status CAS has unit coverage; this native contract uses a namespace.
        migration.status = status  # fsm-bypass: namespace adapter, never a model save.
        for field, value in fields.items():
            setattr(migration, field, value)

    def _store_barrier_state(self, migration: VirtualminMigration, token: UUID, state: dict[str, Any]) -> None:
        assert token == self.token
        migration.barrier_state = state

    def _command(self, migration: VirtualminMigration, server: VirtualminServer, program: str, **params: object) -> None:
        VirtualminMigrationService._command(cast(VirtualminMigrationService, self), migration, server, program, **params)

    def _gateway(self, server: VirtualminServer) -> RecordingGateway:
        return self.nodes[server.pk].gateway

    def _domain(self, server: VirtualminServer, domain: str) -> dict[str, Any]:
        listing = list_migration_domains(self.nodes[server.pk].gateway).unwrap()
        return next(item for item in listing if item["domain"] == domain)


def _release_target_pair(migration: VirtualminMigration) -> None:
    if not migration.barrier_state.get("target_domain_id"):
        return
    released = run_pair_step(
        migration.target_server, {**held_pair_variables(migration), "pair_action": "release"},
        token=str(migration.pk), domain_id=migration.barrier_state["target_domain_id"], timeout_seconds=600,
    )
    assert released.is_ok(), released.unwrap_err() if released.is_err() else ""
    assert released.unwrap().outcome == "released"


@pytest.mark.parametrize("suspended", [False, True])
def test_split_tls_bridge_preserves_scheme_www_and_survives_source_domain_deletion(lab: Lab, request: pytest.FixtureRequest, suspended: bool) -> None:  # noqa: PLR0915  # One real two-node cutover contract, including cleanup.
    state = load_state()
    source_node = state.node("vm-a" if lab.node.key != "vm-a" else "vm-b")
    server = VirtualminServer.objects.get(hostname=source_node.server_hostname)
    source = Lab(RecordingGateway(VirtualminConfig(server=server)), source_node, server, lab.recorder, lab.password)
    request.addfinalizer(lambda: source.remove_domain(DOMAIN))
    request.addfinalizer(lambda: lab.remove_domain(DOMAIN))
    # The bare Virtualmin lab predates the production node playbook's neutral-default step.
    # Reuse that exact asset as the production prerequisite rather than weakening the 404 contract.
    default = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-default-site.conf"
    for node in (source, lab):
        node.exec("test", "-r", "/etc/ssl/private/ssl-cert-snakeoil.key")
        node.exec("install", "-d", "-m", "0755", "/var/www/praho-default")
        _copy(str(default), f"{node.node.container}:/etc/apache2/conf-enabled/praho-default-site.conf")
        node.exec("apache2ctl", "configtest")
        node.exec("apache2ctl", "graceful")
    identity, account_id, lease_token = uuid4(), uuid4(), uuid4()
    archive = f"/var/lib/praho-transfer/migration_{identity}.tar.gz"
    source.remove_domain(DOMAIN)
    lab.remove_domain(DOMAIN)
    source.create_domain(DOMAIN, "contractbridge")
    server.ipv4_address = container_address(source_node.container)
    lab.server.ipv4_address = container_address(lab.node.container)
    domain_id = source.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--id-only").strip()
    owner = source.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--user-only").strip()
    source.exec("sh", "-c", f"printf '%s\\n' '*/5 * * * * /bin/true' | crontab -u '{owner}' -")
    if suspended:
        assert_accepted(source.quiet("disable-domain", {"domain": DOMAIN, "subservers": ""}))
    recorded = run_barrier(server, barrier_variables("record", domain=DOMAIN, domain_id=domain_id,
                                                   token=str(identity)).unwrap()).unwrap()
    assert recorded.ok, recorded.reason
    record = BarrierRecord.from_state(recorded.payload).unwrap()
    applied = run_barrier(server, barrier_variables("apply", domain=DOMAIN, domain_id=domain_id,
                                                  token=str(identity), record=record).unwrap()).unwrap()
    assert applied.ok, applied.reason
    migration = cast(VirtualminMigration, SimpleNamespace(
        pk=identity, account_id=account_id, archive_name=f"migration_{identity}.tar.gz",
        account=SimpleNamespace(domain=DOMAIN, virtualmin_username=owner, template_name="Default Settings",
                                disk_quota_mb=1024, bandwidth_quota_mb=10240,
                                get_recovery_seed=lambda: "bridge-contract-recovery-seed"),
        source_server=server, target_server=lab.server,
        pre_migration_snapshot={"status": "suspended" if suspended else "active", "remote": {"attributes": {"ID": domain_id}}},
        cutover_committed_at=None, barrier_state={"token": str(identity), "record": record.as_state()},
    ))
    source_removed = False
    try:
        assert_accepted(source.quiet("backup-domain", {"domain": DOMAIN, **migration_backup_params(f"migration_{identity}.tar.gz")},
                                     timeout_seconds=BACKUP_TIMEOUT))
        with tempfile.TemporaryDirectory(prefix="praho-lab-bridge-") as spool:
            local = str(Path(spool) / "migration.tar.gz")
            _copy(f"{source_node.container}:{archive}", local)
            lab.exec("install", "-d", "-m", "0700", "/var/lib/praho-transfer")
            _copy(local, f"{lab.node.container}:{archive}")
        checksum = source.exec("sha256sum", archive).split()[0]
        adapter = NativeMigrationAdapter(source, lab, lease_token)
        restore_held_target(cast(VirtualminMigrationService, adapter), migration, lease_token,
                            [{"archive_name": migration.archive_name, "checksum_sha256": checksum}])
        assert lab.exec("passwd", "-S", owner).split()[1] == "L", "restored target Unix account stays locked until commit"
        prepared = prepare_bridge(migration)
        assert prepared.is_ok(), prepared.unwrap_err() if prepared.is_err() else ""
        assert {DOMAIN, f"www.{DOMAIN}"}.issubset(prepared.unwrap().dns_names)
        migration.cutover_committed_at = timezone.now()
        run_held_target_node(migration, "activate")
        activated = activate_target(migration)
        assert activated.is_ok(), activated.unwrap_err() if activated.is_err() else ""
        _release_target_pair(migration)
        if suspended:
            assert DOMAIN in lab.exec("virtualmin", "list-domains", "--disabled", "--name-only").splitlines()
            assert lab.exec("passwd", "-S", owner).split()[1] == "L"
        installed = install_bridge(migration)
        assert installed.is_ok(), installed.unwrap_err() if installed.is_err() else ""
        if suspended:
            # Billing may unsuspend during retention; stale clients must immediately follow the target.
            assert_accepted(lab.quiet("enable-domain", {"domain": DOMAIN, "subservers": ""}))
        changed_cron = "*/7 * * * * /bin/true"
        lab.exec("sh", "-c", f"printf '%s\\n' '{changed_cron}' | crontab -u '{owner}' -")
        replayed = activate_target(migration)
        assert replayed.is_ok(), replayed.unwrap_err() if replayed.is_err() else ""
        assert changed_cron in lab.exec("crontab", "-u", owner, "-l")
        retired = retire_target_activation_data(migration)
        assert retired.is_ok(), retired.unwrap_err() if retired.is_err() else ""
        cleanup_held_target(migration)
        home = lab.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--home-only").strip()
        lab.exec("sh", "-c", f"printf '%s' TARGET-WEB > '{home}/public_html/index.html'")
        lab.exec("sh", "-c", f"printf '%s' '<?php echo empty($_SERVER[\"HTTPS\"]) ? \"HTTP\" : \"HTTPS\"; ?>' > '{home}/public_html/scheme.php'")
        lab.exec("sh", "-c", f"printf '%s' '<?php echo file_put_contents(__DIR__.\"/runtime-write\",\"TARGET-WRITE\")===false?\"WRITE-FAILED\":\"TARGET-WRITE\"; ?>' > '{home}/public_html/write.php'")
        for name in (DOMAIN, f"www.{DOMAIN}"):
            assert source.exec("curl", "-fsS", "--resolve", f"{name}:80:127.0.0.1", f"http://{name}/index.html") == "TARGET-WEB"
            assert source.exec("curl", "-fsS", "--resolve", f"{name}:80:127.0.0.1", f"http://{name}/scheme.php") == "HTTP"
        assert source.exec("curl", "-fsS", "--resolve", f"{DOMAIN}:80:127.0.0.1", f"http://{DOMAIN}/write.php") == "TARGET-WRITE"
        assert lab.exec("stat", "-c", "%U", f"{home}/public_html/runtime-write").strip() == owner
        assert source.exec("curl", "-fsS", "--resolve", f"{DOMAIN}:80:127.0.0.1",
                           "-H", "X-Praho-Original-Host: foreign.invalid", f"http://{DOMAIN}/index.html") == "TARGET-WEB"
        origin = "bridge-" + identity.hex + ".invalid"
        refused = source.exec("curl", "-sS", "--resolve", f"{origin}:443:{lab.server.ipv4_address}",
                              "--cacert", f"/var/lib/praho/bridges/{identity}/origin-ca.pem",
                              "-H", "X-Praho-Original-Host: foreign.invalid", "-o", "/dev/null", "-w", "%{http_code}",
                              f"https://{origin}/index.html")
        assert refused == "403", "the private origin never forwards an unowned Host"
        assert source.exec("curl", "-fsS", "--cacert", f"/var/lib/praho/bridges/{identity}/upstream-ca.pem",
                           "--resolve", f"{DOMAIN}:443:127.0.0.1", f"https://{DOMAIN}/scheme.php") == "HTTPS"
        default = source.exec("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                              "-H", "Host: unclaimed.invalid", "http://127.0.0.1/")
        assert default == "404"
        source.remove_domain(DOMAIN)
        source_removed = True
        source.exec("test", "!", "-e", f"/etc/apache2/sites-enabled/{DOMAIN}.conf")
        source.exec("test", "-r", f"/etc/apache2/conf-enabled/praho-migration-{identity}.conf")
        source.exec("apache2ctl", "configtest")
        verified = verify_bridge(migration)
        assert verified.is_ok(), verified.unwrap_err() if verified.is_err() else ""
        assert source.exec("curl", "-fsS", "--resolve", f"{DOMAIN}:80:127.0.0.1", f"http://{DOMAIN}/index.html") == "TARGET-WEB"
    finally:
        _release_target_pair(migration)
        if migration.barrier_state.get("target_domain_id"):
            cleanup_held_target(migration)
        removed = remove_bridge(migration, source_removed=source_removed)
        assert removed.is_ok(), removed.unwrap_err() if removed.is_err() else ""
        if source_removed:
            source.exec("test", "!", "-e", f"/var/lib/praho/migration/migration-{domain_id}.{identity}.crontab")
        source.remove_domain(DOMAIN)
        lab.remove_domain(DOMAIN)
        for node in (source, lab):
            node.exec("rm", "-f", "--", archive, archive + ".dom", archive + ".info")
        source.exec("rm", "-f", "--", f"/var/lib/praho/migration/migration-{domain_id}.{identity}.crontab")
