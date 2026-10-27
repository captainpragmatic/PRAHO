"""Run virtualmin_recovery.yml through the real recovery service, preserving held Unix/HTTP and unsuspension."""

from __future__ import annotations

import secrets
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest

from apps.provisioning.management.commands._virtualmin_lab import load_state
from apps.provisioning.virtualmin_gateway import VirtualminConfig
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import migration_backup_params
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_pair_restore import run_pair_step
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from apps.provisioning.virtualmin_service import create_domain_params
from tests.virtualmin_lab.contract.harness import BACKUP_TIMEOUT, Lab, RecordingGateway, assert_accepted

DOMAIN = "contractrecovery.praho.test"
OWNER = "contractrecovery"


def _copy(source: str, target: str) -> None:
    subprocess.run(["docker", "cp", source, target], check=True, capture_output=True, timeout=60)  # noqa: S603, S607  # Fixed local Docker command


def _shadow_digest(node: Lab) -> str:
    return node.exec("sh", "-c", f"getent shadow {OWNER} | cut -d: -f2 | sha256sum").strip()


def _install_database_probe(source: Lab, domain_id: str) -> None:
    """The archived app retains its original login; neither passwords nor hashes enter argv/output."""
    program = '''import base64, os, pwd
from pathlib import Path
fields = dict(line.split("=", 1) for line in Path("/etc/webmin/virtual-server/domains/DOMAIN_ID").read_text().splitlines() if "=" in line)
encode = lambda value: base64.b64encode(value.encode()).decode()
user = fields.get("mysql_user") or fields["user"]
password = fields.get("mysql_pass") or fields.get("pass", "")
database = fields["db_mysql"].split()[0]
arguments = ",".join('base64_decode("' + encode(value) + '")' for value in ("localhost", user, password, database))
php = '<?php try { $db = new mysqli(' + arguments + '); $db->query("CREATE TEMPORARY TABLE praho_contract_probe (value INT)"); $db->query("INSERT INTO praho_contract_probe VALUES (1)"); $db->query("UPDATE praho_contract_probe SET value=2"); $result=$db->query("SELECT value FROM praho_contract_probe")->fetch_row(); $db->query("DELETE FROM praho_contract_probe"); $db->query("DROP TEMPORARY TABLE praho_contract_probe"); echo $result[0]==2?"DB-OK":"DB-FAIL"; } catch (Throwable $e) { echo "DB-FAIL"; } ?>'
path = Path(fields["home"]) / "public_html/db-proof.php"
path.write_text(php)
owner = pwd.getpwnam(fields["user"])
os.chown(path, owner.pw_uid, owner.pw_gid)
path.chmod(0o600)
'''
    source.exec("python3", "-c", program.replace("DOMAIN_ID", domain_id))


def _database_probe(node: Lab) -> str:
    return node.exec("curl", "-fsS", "--resolve", f"{DOMAIN}:80:127.0.0.1", f"http://{DOMAIN}/db-proof.php")


@pytest.mark.parametrize("suspended", [False, True])
def test_recovery_holds_restored_unix_and_preserves_archived_credentials(lab: Lab, suspended: bool) -> None:  # noqa: PLR0915  # One real restore lifecycle, with exact cleanup
    source_node = load_state().node("vm-a" if lab.node.key != "vm-a" else "vm-b")
    server = VirtualminServer.objects.get(hostname=source_node.server_hostname)
    source = Lab(RecordingGateway(VirtualminConfig(server=server)), source_node, server, lab.recorder, lab.password)
    source.remove_domain(DOMAIN)
    lab.remove_domain(DOMAIN)
    identity = uuid4()
    archive = f"virtualmin_backup_{identity.hex}.tar.gz"
    remote = f"/var/lib/praho-transfer/{archive}"
    target_id = ""
    foreign_cert_dir = ""
    ca_dir = ""
    try:
        source.create_domain(DOMAIN, OWNER)
        ca_dir = source.exec("mktemp", "-d", "/tmp/praho-recovery-ca.XXXXXX").strip()  # noqa: S108  # Private disposable lab CA
        source.exec(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
            "/CN=PRAHO Recovery Contract CA", "-keyout", f"{ca_dir}/ca.key", "-out", f"{ca_dir}/ca.pem",
        )
        source.exec(
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={DOMAIN}",
            "-keyout", f"{ca_dir}/site.key", "-out", f"{ca_dir}/site.csr",
        )
        source.exec(
            "openssl", "x509", "-req", "-in", f"{ca_dir}/site.csr", "-CA", f"{ca_dir}/ca.pem",
            "-CAkey", f"{ca_dir}/ca.key", "-CAcreateserial", "-days", "2", "-out", f"{ca_dir}/site.pem",
        )
        assert_accepted(source.quiet("install-cert", {
            "domain": DOMAIN, "cert": f"{ca_dir}/site.pem", "key": f"{ca_dir}/site.key", "ca": f"{ca_dir}/ca.pem",
        }))
        source_chain = source.exec(
            "sh", "-c", f"openssl s_client -connect 127.0.0.1:443 -servername {DOMAIN} -showcerts </dev/null 2>/dev/null",
        ).count("-----BEGIN CERTIFICATE-----")
        assert source_chain == 2, "the backup fixture must really serve its complete certificate chain"
        original_hash = _shadow_digest(source)
        source_id = source.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--id-only").strip()
        _install_database_probe(source, source_id)
        assert _database_probe(source) == "DB-OK", "the source app must have real database login and write grants"
        source.exec(
            "sh",
            "-c",
            f"printf '%s\\n' 'MAILTO=owner@example.test' '0 0 1 1 * /bin/true' '# 0 0 1 1 * /bin/false' | crontab -u {OWNER} -",
        )
        if suspended:
            assert_accepted(source.quiet("disable-domain", {"domain": DOMAIN, "subservers": ""}))
        source_id = source.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--id-only").strip()
        original_certificate = source.exec(
            "openssl", "x509", "-in", f"/etc/ssl/virtualmin/{source_id}/ssl.cert", "-noout", "-fingerprint", "-sha256"
        ).strip()
        assert_accepted(
            source.quiet(
                "backup-domain", {"domain": DOMAIN, **migration_backup_params(archive)}, timeout_seconds=BACKUP_TIMEOUT
            )
        )
        checksum = source.exec("sha256sum", remote).split()[0]
        with tempfile.TemporaryDirectory(prefix="praho-recovery-contract-") as directory:
            local = str(Path(directory) / archive)
            _copy(f"{source_node.container}:{remote}", local)
            lab.exec("install", "-d", "-m", "0700", "/var/lib/praho-transfer")
            _copy(local, f"{lab.node.container}:{remote}")
        source.remove_domain(DOMAIN)
        assert_accepted(
            lab.quiet(
                "create-domain",
                create_domain_params(
                    domain=DOMAIN,
                    username=OWNER,
                    password=secrets.token_urlsafe(48),
                    template="Default Settings",
                    recovery_seed="contract-recovery-seed",
                    disk_quota_mb=1024,
                    bandwidth_quota_mb=10240,
                ),
            )
        )
        assert_accepted(lab.quiet("disable-domain", {"domain": DOMAIN, "subservers": ""}))
        target_id = lab.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--id-only").strip()
        assert target_id != source_id
        # The archived namespace is occupied: a native restore must never write another tenant's
        # certificate files. Only this test's synthetic sentinels are created and removed here.
        candidate_cert_dir = f"/etc/ssl/virtualmin/{source_id}"
        exists = lab.exec("python3", "-c", f"from pathlib import Path; print(int(Path('{candidate_cert_dir}').exists()))")
        assert exists.strip() == "0", "refuse to alter a pre-existing target certificate namespace"
        lab.exec("install", "-d", "-m", "0700", candidate_cert_dir)
        foreign_cert_dir = candidate_cert_dir
        for filename in ("ssl.cert", "ssl.key", "ssl.combined", "ssl.ca"):
            lab.exec("sh", "-c", f"printf '%s' 'foreign-certificate-sentinel' > '{foreign_cert_dir}/{filename}'")
        migration = cast(
            VirtualminMigration,
            SimpleNamespace(
                pk=identity,
                account=SimpleNamespace(domain=DOMAIN, virtualmin_username=OWNER),
                target_server=lab.server,
                pre_migration_snapshot={"status": "suspended" if suspended else "active"},
                barrier_state={
                    "target_domain_id": target_id,
                    "recovery_archives": [{"archive_name": archive, "checksum_sha256": checksum}],
                },
            ),
        )
        recovery = VirtualminRecoveryService()
        recovery._node(migration, "stage")
        variables = {
            **recovery._pair_variables(migration),
            "pair_action": "restore",
            "pair_recovery": True,
            "pair_base_archive": archive,
            "pair_base_sha": checksum,
        }
        restored = run_pair_step(
            lab.server, variables, token=str(identity), domain_id=target_id, timeout_seconds=BACKUP_TIMEOUT + 180
        )
        assert restored.is_ok(), restored.unwrap_err() if restored.is_err() else ""
        assert restored.unwrap().outcome == "ok"
        assert restored.unwrap().barrier_broken() is None
        assert lab.exec("passwd", "-S", OWNER).split()[1] == "L", "target Unix login stays locked before commit"
        for filename in ("ssl.cert", "ssl.key", "ssl.combined", "ssl.ca"):
            assert lab.exec("cat", f"{foreign_cert_dir}/{filename}") == "foreign-certificate-sentinel"
        assert _shadow_digest(lab) != original_hash
        code = lab.exec(
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"Host: {DOMAIN}", "http://127.0.0.1/"
        )
        assert code == "503"
        recovery._node(migration, "activate")
        released = run_pair_step(
            lab.server,
            {**recovery._pair_variables(migration), "pair_action": "release"},
            token=str(identity),
            domain_id=target_id,
            timeout_seconds=180,
        )
        assert released.is_ok() and released.unwrap().outcome == "released"
        if suspended:
            assert _shadow_digest(lab) != original_hash
            assert "# VIRTUALMIN DISABLE" in lab.exec("crontab", "-u", OWNER, "-l")
        assert_accepted(lab.quiet("enable-domain", {"domain": DOMAIN, "subservers": ""}))
        assert _database_probe(lab) == "DB-OK", "the restored app keeps its original database credential and write grants"
        served_certificate = lab.exec(
            "sh", "-c", f"openssl s_client -connect 127.0.0.1:443 -servername {DOMAIN} </dev/null 2>/dev/null "
            "| openssl x509 -noout -fingerprint -sha256",
        ).strip()
        assert served_certificate == original_certificate
        served_chain = lab.exec(
            "sh", "-c", f"openssl s_client -connect 127.0.0.1:443 -servername {DOMAIN} -showcerts </dev/null 2>/dev/null",
        ).count("-----BEGIN CERTIFICATE-----")
        assert served_chain == source_chain, "recovery preserves the customer certificate's full served chain"
        assert _shadow_digest(lab) == original_hash
        cron = lab.exec("crontab", "-u", OWNER, "-l")
        assert "MAILTO=owner@example.test" in cron
        assert "# VIRTUALMIN DISABLE" not in cron
        assert "# 0 0 1 1 * /bin/false" in cron
        lab.exec("sh", "-c", f"printf '%s\\n' '# customer changed cron' | crontab -u {OWNER} -")
        recovery._node(migration, "activate")
        assert lab.exec("crontab", "-u", OWNER, "-l").strip() == "# customer changed cron"
    finally:
        source.remove_domain(DOMAIN)
        lab.remove_domain(DOMAIN)
        for node in (source, lab):
            for suffix in ("", ".dom", ".info"):
                node.exec("rm", "-f", remote + suffix)
        for suffix in ("cron", "json", "activation"):
            lab.exec("rm", "-f", f"/var/lib/praho/recovery/{identity}.{suffix}")
        if target_id:
            lab.exec("rm", "-f", f"/etc/apache2/conf-enabled/zz-praho-maint-{target_id}.conf")
            lab.exec("apache2ctl", "graceful")
        if foreign_cert_dir:
            for filename in ("ssl.cert", "ssl.key", "ssl.combined", "ssl.ca"):
                lab.exec("rm", "-f", f"{foreign_cert_dir}/{filename}")
            lab.exec("rmdir", foreign_cert_dir)
        if ca_dir:
            source.exec("rm", "-rf", "--", ca_dir)
