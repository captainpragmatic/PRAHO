#!/usr/bin/env python3
"""Destructive quota acceptance ONLY inside the exact disposable provider VM.

Uploaded by provider_vm.py after provider-label/host-key verification. Acceptance
is published only after real UID/PHP/DB failures, neighbor commits, reboot and update.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import UUID, uuid4

sys.path.insert(0, "/usr/local/lib/praho")

LIMIT_KIB = 64 * 1024
MAX_INSERTS = 128
STATE = Path("/root/praho-native-quota-state.json")
OWNER = Path("/root/praho-native-lab-owner")
VMIN = "/usr/sbin/virtualmin"


def run(
    argv: list[str], *, payload: str | None = None, timeout: int = 120, allow_error: bool = False
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 -- Fixed fixture executables and argv; no shell interpolation.
        argv,
        input=payload,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode and not allow_error:
        raise AssertionError("Native fixture operation failed: " + result.stderr[-1500:])
    return result


def sql(query: str, *, allow_error: bool = False) -> subprocess.CompletedProcess[str]:
    return run(
        ["/usr/bin/mariadb", "--protocol=socket", "--batch", "--raw", "--skip-column-names", "--execute", query],
        timeout=30,
        allow_error=allow_error,
    )


def save(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


MIN_FREE_FOR_QUOTA_PROOF = 1024**3


def fixture_domains(run_id: str) -> tuple[str, str]:
    stem = "q776" + UUID(run_id).hex[:8]
    return stem + ".example.invalid", stem + "n.example.invalid"


def domain_row(domain: str) -> dict[str, str]:
    from praho_quota_native import _fields  # noqa: PLC0415 -- Installed production probe.

    matches = [_fields(path) for path in Path("/etc/webmin/virtual-server/domains").iterdir() if path.name.isdigit()]
    rows = [row for row in matches if row.get("dom") == domain]
    if len(rows) != 1:
        raise AssertionError("Native acceptance requires one exact fixture domain")
    return rows[0]


def unexpected_domains(rows: list[dict[str, str]], fixtures: tuple[str, str], fqdn: str) -> list[str]:
    """Domains other than this run's fixtures and Virtualmin's own default hostname domain.

    Virtualmin creates that domain for the node's hostname (it backs the hostname certificate): it is marked
    defaulthostdomain=1 and owned by _hostname with the hidden /home/._hostname."""
    return [
        row.get("dom", "")
        for row in rows
        if row.get("dom") not in fixtures
        and not (
            row.get("defaulthostdomain") == "1"
            and row.get("user") == "_hostname"
            and row.get("home") == "/home/._hostname"
            and row.get("dom") == fqdn
        )
    ]


def prepare(run_id: str) -> None:
    from praho_quota_native import _fields  # noqa: PLC0415 -- Exact native inventory.

    domains = fixture_domains(run_id)
    existing = [_fields(path) for path in Path("/etc/webmin/virtual-server/domains").iterdir() if path.name.isdigit()]
    if unexpected := unexpected_domains(existing, domains, Path("/etc/hostname").read_text().strip()):
        raise AssertionError("This is no longer an empty owned native test node: " + ", ".join(unexpected[:5]))
    for index, domain in enumerate(domains):
        if any(row.get("dom") == domain for row in existing):
            continue
        username = "q776" + UUID(run_id).hex[:8] + ("n" if index else "")
        run(
            [
                VMIN,
                "create-domain",
                "--domain",
                domain,
                "--user",
                username,
                "--pass",
                str(uuid4()) + str(uuid4()),
                "--unix",
                "--dir",
                "--web",
                "--ssl",
                "--logrotate",
                "--mysql",
                "--quota",
                str(LIMIT_KIB),
                "--uquota",
                str(LIMIT_KIB),
                "--no-email",
            ],
            timeout=180,
        )
    for domain in domains:
        row = domain_row(domain)
        name = row["user"] + "_quota"
        if name not in row.get("db_mysql", "").split():
            run([VMIN, "create-database", "--domain", domain, "--name", name, "--type", "mysql"])


def probe(domain: str) -> dict[str, object]:
    from praho_quota_native import NativeQuotaBackend, _read  # noqa: PLC0415 -- Actual production readback.

    row = domain_row(domain)
    evidence = NativeQuotaBackend().probe(
        {
            "identity": {
                "installation": _read(Path("/var/lib/praho/usage/installation")).strip(),
                "domain_id": row["id"],
                "domain": domain,
                "uid": int(row["uid"]),
                "gid": int(row["gid"]),
            }
        }
    )
    for field in ("uid_soft_kib", "uid_hard_kib", "gid_soft_kib", "gid_hard_kib"):
        if evidence[field] != LIMIT_KIB:
            raise AssertionError("Normal native create/reboot/update did not retain equal hard UID/GID caps")
    return evidence


def unprivileged(domain: str, *, php: bool) -> None:
    row = domain_row(domain)
    account = pwd.getpwnam(row["user"])
    target = Path(account.pw_dir) / "native-quota-denial.bin"
    if target.exists():
        target.unlink()
    prefix = [
        "/usr/bin/setpriv",
        "--reuid",
        str(account.pw_uid),
        "--regid",
        str(account.pw_gid),
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
    ]
    if php:
        # At the cap the kernel returns EDQUOT to PHP's write(), but PHP 8.5's fwrite reports it as a short count
        # (0) with no error_get_last() message (traced on Ubuntu 26.04). So any short write counts as the denial,
        # and the check below then requires usage at the verified hard cap, which tells a quota stop apart from
        # any other write failure.
        program = r"""$p=$argv[1]; $f=fopen($p,'wb'); $hit=false;
for($i=0;$i<128;$i++) { $n=@fwrite($f,str_repeat('x',1048576));
if($n!==1048576) {$hit=true;break;}
if(!fflush($f)||!fsync($f)){break;}}
fclose($f); if(!$hit){fwrite(STDERR,'PHP did not encounter EDQUOT');exit(7);} echo posix_geteuid();"""
        result = run([*prefix, "/usr/bin/php8.5", "-r", program, str(target)])
        if result.stdout.strip() != str(account.pw_uid):
            raise AssertionError("PHP quota proof used the wrong runtime identity")
        # PHP gives no errno here: plenty of free disk rules out ENOSPC as the reason for the short write.
        space = os.statvfs(account.pw_dir)
        if space.f_bavail * space.f_frsize < MIN_FREE_FOR_QUOTA_PROOF:
            raise AssertionError("PHP's short write cannot prove a quota stop on a nearly full disk")
    else:
        program = """import errno,json,os,sys
assert os.geteuid()==int(sys.argv[2]) and os.getegid()==int(sys.argv[3])
status=open('/proc/self/status').read(); assert int(status.split('CapEff:')[1].split()[0],16)==0
hit=False
with open(sys.argv[1],'wb',buffering=0) as stream:
 for i in range(128):
  try: stream.write(b'x'*1048576); os.fsync(stream.fileno())
  except OSError as error:
   assert error.errno==errno.EDQUOT,error
   hit=True; break
assert hit,'unprivileged writer did not encounter EDQUOT'
print('uid-edquot')
"""
        run([*prefix, "/usr/bin/python3", "-c", program, str(target), str(account.pw_uid), str(account.pw_gid)])
    current = probe(domain)
    if max(current["uid_used_bytes"], current["gid_used_bytes"]) < (LIMIT_KIB - 2048) * 1024:
        raise AssertionError("Write failure was not at the verified tenant hard cap")
    target.unlink()
    os.sync()


def _has_os_edquot(diagnostic: str) -> bool:
    return (
        re.search(
            r"\b(disk quota exceeded|errno(?:\s*[=:]\s*|\s+)122|(?:operating system|os) error(?: number)?\s+122)\b",
            diagnostic,
            re.I,
        )
        is not None
    )


def _verify_neighbor_commit(schema: str, *, database_pid: str) -> None:
    from praho_quota_native import (  # noqa: PLC0415 -- Actual writer readback after commit.
        _database_writer_qualified,
        _run,
    )

    # The fixture schema was validated by database(); negative IDs do not advance AUTO_INCREMENT.
    marker = -(uuid4().int % ((1 << 63) - 1) + 1)
    before = int(sql(f"SELECT COUNT(*) FROM `{schema}`.quota_neighbor").stdout.strip())  # noqa: S608 -- Exact generated schema validated by caller.
    sql(
        f"START TRANSACTION; INSERT INTO `{schema}`.quota_neighbor (id) VALUES ({marker}); COMMIT;"  # noqa: S608 -- Exact generated schema and local bounded integer.
    )
    after = int(sql(f"SELECT COUNT(*) FROM `{schema}`.quota_neighbor").stdout.strip())  # noqa: S608 -- Exact generated schema validated by caller.
    stored = sql(f"SELECT id FROM `{schema}`.quota_neighbor WHERE id={marker}").stdout.strip()  # noqa: S608 -- Exact generated schema and local bounded integer.
    if after != before + 1 or stored != str(marker):
        raise AssertionError("The neighboring tenant did not commit its independent post-denial marker")
    _database_writer_qualified()
    if _run(["/usr/bin/systemctl", "show", "mariadb", "--property=MainPID", "--value"]) != database_pid:
        raise AssertionError("The post-denial neighbor commit restarted MariaDB")


def database(domain: str, neighbor: str) -> None:
    from praho_quota_native import _database_writer_qualified, _run, _set_kernel_quota  # noqa: PLC0415

    row, neighbor_row = domain_row(domain), domain_row(neighbor)
    database_name, neighbor_name = row["user"] + "_quota", neighbor_row["user"] + "_quota"
    if any(re.fullmatch(r"q776[0-9a-f]{8}n?_quota", name) is None for name in (database_name, neighbor_name)):
        raise AssertionError("Refuse SQL outside the exact generated fixture schemas")
    _database_writer_qualified()
    pid = _run(["/usr/bin/systemctl", "show", "mariadb", "--property=MainPID", "--value"])
    sql(
        f"CREATE TABLE IF NOT EXISTS `{database_name}`.quota_fill (id BIGINT PRIMARY KEY AUTO_INCREMENT, data LONGBLOB) ENGINE=InnoDB ROW_FORMAT=DYNAMIC"
    )
    sql(
        f"CREATE TABLE IF NOT EXISTS `{neighbor_name}`.quota_neighbor (id BIGINT PRIMARY KEY AUTO_INCREMENT) ENGINE=InnoDB"
    )
    probe(domain)  # Includes the actual existing physical per-table and setgid checks.
    stop = Event()
    commits = []

    def neighbor_writes() -> None:
        while not stop.is_set():
            sql(f"INSERT INTO `{neighbor_name}`.quota_neighbor VALUES (NULL)")  # noqa: S608 -- Strict generated schema above.
            commits.append(True)
            stop.wait(0.02)

    began = datetime.now(UTC).isoformat()
    failure = None
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(neighbor_writes)
        try:
            for _index in range(MAX_INSERTS):
                attempted = sql(
                    f"INSERT INTO `{database_name}`.quota_fill (data) VALUES (REPEAT('x',1048576))",  # noqa: S608 -- Exact bounded ASCII fixture schema validated above.
                    allow_error=True,
                )
                if attempted.returncode:
                    failure = attempted
                    break
            # Force a table flush too: server acknowledgement alone is not physical enforcement proof.
            sql(f"FLUSH TABLES `{database_name}`.quota_fill", allow_error=True)
        finally:
            stop.set()
            future.result(timeout=30)
    current = probe(domain)
    logs = run(["/usr/bin/journalctl", "-u", "mariadb", "--since", began, "--no-pager", "--output=cat"]).stdout
    if failure is None or not _has_os_edquot(failure.stderr + "\n" + logs):
        raise AssertionError("The real MariaDB writer did not prove EDQUOT")
    if len(commits) < 3 or _run(["/usr/bin/systemctl", "show", "mariadb", "--property=MainPID", "--value"]) != pid:
        raise AssertionError("Quota exhaustion interrupted the neighboring tenant or restarted MariaDB")
    _verify_neighbor_commit(neighbor_name, database_pid=pid)
    if current["gid_used_bytes"] < (LIMIT_KIB - 2048) * 1024:
        raise AssertionError("Database failure was not at the tenant group cap")
    # Only this owned lab fixture gets temporary cleanup headroom. Customer code never uses this bypass.
    mount = json.loads(_run(["/usr/bin/findmnt", "--json", "--target", row["home"], "--output", "SOURCE"]))[
        "filesystems"
    ][0]["source"]
    _set_kernel_quota(mount, int(row["gid"]), LIMIT_KIB * 2, group=True)
    try:
        sql(f"DROP TABLE `{database_name}`.quota_fill")
        sql(f"TRUNCATE TABLE `{neighbor_name}`.quota_neighbor")
    finally:
        _set_kernel_quota(mount, int(row["gid"]), LIMIT_KIB, group=True)
    probe(domain)


def requalify() -> dict[str, object]:
    from praho_hosting_node import (  # noqa: PLC0415 -- Installed production recovery.
        REQUALIFICATION_ROOT,
        inspect,
        perform,
    )

    acceptance = Path("/var/lib/praho/hosting/native-acceptance.json")
    before = json.loads(acceptance.read_text())
    reviewed = inspect("0" * 64)
    if reviewed["quota"].get("requalification_required") is not True:
        raise AssertionError("Native recovery fixture did not establish a new unqualified boot")
    token = str(uuid4())
    result = perform("quota_policy", {"identity": "0" * 64, "token": token})
    fresh = json.loads(acceptance.read_text())
    if (
        result.get("fenced_token") != token
        or result["quota"].get("requalification_required") is not False
        or fresh["boot_id"] == before["boot_id"]
        or fresh["acceptance_id"] != before["acceptance_id"]
        or fresh.get("qualification_id") == before.get("qualification_id", before["acceptance_id"])
        or not fresh.get("original_digest")
        or REQUALIFICATION_ROOT.exists()
        or Path("/var/lib/praho/hosting/requalification-probe.json").exists()
    ):
        raise AssertionError("Native isolated recovery or cleanup did not satisfy fresh qualification")
    return {"phase": "requalify", "verified": True, "boot_id": fresh["boot_id"], "isolated_requalification": True}


def upgrade() -> dict[str, object]:
    run(["/usr/bin/apt-get", "update"], timeout=300)
    run(["/usr/bin/apt-get", "--assume-yes", "upgrade"], timeout=1200)
    owner = Path("/var/lib/praho/hosting/notification-owner")
    if owner.exists() and owner.read_text().strip() == "platform":
        run(
            ["/usr/bin/python3", "/usr/local/lib/praho/praho_hosting_node.py", "reconcile"],
            payload=json.dumps({"identity": "0" * 64}),
        )
    state = json.loads(STATE.read_text())
    state["packages_updated"] = True
    save(STATE, state)
    return {"reboot_required": Path("/var/run/reboot-required").exists()}


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 3:
        raise ValueError("An exact disposable native VM owner and phase are required")
    run_id, phase = sys.argv[1:]
    if str(UUID(run_id)) != run_id or OWNER.read_text().strip() != run_id:
        raise ValueError("This is not the exact owned native VM")
    if phase not in {"initial", "reboot", "update", "upgrade", "requalify"}:
        raise ValueError("Unsupported native acceptance phase")
    if phase in {"upgrade", "requalify"}:
        print(json.dumps(upgrade() if phase == "upgrade" else requalify()))
        return
    prepare(run_id)
    domain, neighbor = fixture_domains(run_id)
    for php in (False, True):
        unprivileged(domain, php=php)
    database(domain, neighbor)
    evidence = probe(domain)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if phase == "initial":
        state = {
            "run": run_id,
            "initial_boot": boot,
            "filesystem_uuid": evidence["identity"]["filesystem_uuid"],
            "initial": True,
        }
    else:
        state = json.loads(STATE.read_text())
        if (
            state["run"] != run_id
            or boot == state["initial_boot"]
            or state["filesystem_uuid"] != evidence["identity"]["filesystem_uuid"]
        ):
            raise AssertionError("Native reboot or filesystem identity proof failed")
        state[phase] = True
    save(STATE, state)
    if phase == "update":
        if not all(state.get(key) is True for key in ("initial", "reboot", "packages_updated", "update")):
            raise AssertionError("Reboot and managed update acceptance must precede readiness")
        from praho_hosting_node import filesystem, quota_format  # noqa: PLC0415

        proof = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "installation": evidence["identity"]["installation"],
            "filesystem_uuid": state["filesystem_uuid"],
            "boot_id": boot,
            "os": "ubuntu-26.04",
            "php": "8.5",
            "filesystem": "ext4",
            "quota_format": quota_format(filesystem()["source"]),
            "root_filesystem": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "mysql_cap_sys_resource": False,
            "mysql_bounding_cap_sys_resource": False,
            "physical_tables_verified": True,
            "acceptance": dict.fromkeys(
                (
                    "unprivileged_uid_edquot",
                    "php_uid_edquot",
                    "database_edquot",
                    "database_neighbor_healthy",
                    "reboot_persistent",
                    "update_persistent",
                ),
                True,
            ),
            "acceptance_id": str(uuid4()),
        }
        save(Path("/var/lib/praho/hosting/native-acceptance.json"), proof)
    print(json.dumps({"phase": phase, "verified": True, "boot_id": boot}))


if __name__ == "__main__":
    main()
