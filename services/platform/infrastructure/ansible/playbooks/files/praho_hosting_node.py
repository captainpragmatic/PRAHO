#!/usr/bin/env python3
"""Root native node preparation, read-only inventory and fenced mail handover.

No occupied-filesystem format conversion and no quotaoff operation exists here.
Native acceptance is written only by the disposable VM acceptance runner.
"""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from threading import Event
from time import monotonic
from uuid import UUID

LIMIT = 65536
FSTAB_MIN_FIELDS = 4
COMMAND_ARGUMENTS = 2
MAX_OPERATOR_EMAILS = 25
STATE = Path("/var/lib/praho/hosting")
INSTALLATION = Path("/var/lib/praho/usage/installation")
PERL_ADAPTER = Path("/usr/local/lib/praho/praho-notification-policy.pl")
OS_QUOTA_CRON_SHA256 = "e34d72322f0a58df9d06a0bfd68709efc4801964a8c9b64a7bc0b6e19d9e0f35"
REQUALIFICATION_UID_MIN = 2147000000
REQUALIFICATION_UID_COUNT = 32
REQUALIFICATION_LIMIT_KIB = 64
REQUALIFICATION_ROOT = Path("/var/lib/praho-quota-requalification")
ACCEPTANCE_CHECKS = (
    "unprivileged_uid_edquot",
    "php_uid_edquot",
    "database_edquot",
    "database_neighbor_healthy",
    "reboot_persistent",
    "update_persistent",
)
QUALIFICATION_FIELDS = (
    "schema",
    "policy_version",
    "installation",
    "filesystem_uuid",
    "boot_id",
    "os",
    "php",
    "filesystem",
    "quota_format",
    "root_filesystem",
    "uid_enforced",
    "gid_enforced",
    "mysql_cap_sys_resource",
    "mysql_bounding_cap_sys_resource",
    "physical_tables_verified",
    "acceptance",
    "acceptance_id",
)
ACME_OWNER_BRANCH = """\tif ($d->{'letsencrypt_email'} == 0 ||
\t    $d->{'letsencrypt_email'} == 1 && !$ok) {
\t\t&send_notify_email(
\t\t\t$from, [$d], $d, $subject, $body, undef,
\t\t\tundef, undef, undef, undef, undef,
\t\t\t$d->{'letsencrypt_email_master'} ?
\t\t\t\t$gconfig{'webmin_email_to'} : undef);
\t\t}"""
ACME_MASTER_BRANCH = """
\telsif ($d->{'letsencrypt_email_master'}) {
\t\t# PRAHO: customer notifications belong to Platform; preserve explicit master alerts.
\t\t&send_notify_email($from, [{ %$d, 'emailto' => $gconfig{'webmin_email_to'} }],
\t\t\t$d, $subject, $body);
\t\t}"""
ACME_GUARDED_OWNER_BRANCH = ACME_OWNER_BRANCH.replace(
    "\tif (",
    "\trequire '/usr/local/lib/praho/praho-notification-policy.pl';\n\tif (&praho_native_customer_notifications() && (",
    1,
).replace("&& !$ok) {", "&& !$ok)) {", 1)


def notification_source_patches(status: str, ssl: str) -> tuple[str, str]:
    for variable in ("$serv", "$certserv"):
        original = variable + "->{'email'} = $d->{'emailto'};"
        replacement = variable + "->{'email'} = &monitor_email($d); # PRAHO customer-mail ownership"
        if status.count(original) == 1 and status.count(replacement) == 0:
            status = status.replace(original, replacement)
        elif status.count(original) != 0 or status.count(replacement) != 1:
            raise ValueError("Unknown Virtualmin existing-monitor recipient source shape")
    complete = ACME_GUARDED_OWNER_BRANCH + ACME_MASTER_BRANCH
    if ssl.count(complete) == 1 and ssl.count(ACME_OWNER_BRANCH) == 0 and ssl.count(ACME_MASTER_BRANCH) == 1:
        return status, ssl
    previous = ACME_OWNER_BRANCH + ACME_MASTER_BRANCH
    if ssl.count(previous) == 1 and ssl.count(ACME_OWNER_BRANCH) == 1 and ssl.count(ACME_MASTER_BRANCH) == 1:
        return status, ssl.replace(previous, complete)
    if ssl.count(ACME_OWNER_BRANCH) != 1 or "# PRAHO: customer notifications" in ssl:
        raise ValueError("Unknown Virtualmin ACME notification source shape")
    return status, ssl.replace(ACME_OWNER_BRANCH, complete)


def os_quota_notification_inventory() -> tuple[bool, str]:
    """Recognize the supported stock OS route without executing imported shell configuration."""
    values: dict[str, str | None] = {}
    for filename in ("/etc/cron.daily/quota", "/etc/default/quota"):
        try:
            values[filename] = _read(Path(filename))
        except FileNotFoundError:
            values[filename] = None
        except (OSError, ValueError):
            values[filename] = "unreadable"
    digests = {
        name: None if value is None else hashlib.sha256(value.encode()).hexdigest() for name, value in values.items()
    }
    digest = hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest()
    cron, defaults = values.values()
    if cron is not None and hashlib.sha256(cron.encode()).hexdigest() != OS_QUOTA_CRON_SHA256:
        return False, digest
    if defaults is None:
        return True, digest  # The exact stock cron exits without a defaults file.
    assignments = {}
    for line in defaults.split("\n"):
        if not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
            continue
        match = re.fullmatch(
            r"[ \t]*(run_warnquota|RPCRQUOTADOPTS)=(?:\"([^\"$`\\]*)\"|'([^']*)'|([A-Za-z0-9_./:=-]*))"
            r"(?:[ \t]+#.*|[ \t]*)",
            line,
        )
        if match is None or match[1] in assignments:
            return False, digest
        assignments[match[1]] = next(value for value in match.groups()[1:] if value is not None)
    return "run_warnquota" in assignments and assignments["run_warnquota"] in {"", "false"}, digest


def notification_guard_inventory() -> tuple[bool, str]:
    """An old domain flag is safe only with the actual guarded source and persisted ownership."""
    root = Path("/usr/share/webmin/virtual-server")
    paths = (root / "feature-status.pl", root / "feature-ssl.pl", STATE / "notification-owner")
    values: list[str | None] = []
    for path in paths:
        try:
            values.append(_read(path, limit=1024 * 1024 if path != paths[-1] else LIMIT))
        except FileNotFoundError:
            values.append(None)
        except (OSError, ValueError):
            values.append("unreadable")
    digest = hashlib.sha256(
        json.dumps([None if value is None else hashlib.sha256(value.encode()).hexdigest() for value in values]).encode()
    ).hexdigest()
    status, ssl, owner = values
    if status is None or ssl is None or owner != "platform\n":
        return False, digest
    try:
        return notification_source_patches(status, ssl) == (status, ssl), digest
    except ValueError:
        return False, digest


def _apply_notification_source_patches() -> None:
    root = Path("/usr/share/webmin/virtual-server")
    status_path, ssl_path = root / "feature-status.pl", root / "feature-ssl.pl"
    status, ssl = _read(status_path, limit=1024 * 1024), _read(ssl_path, limit=1024 * 1024)
    corrected_status, corrected_ssl = notification_source_patches(status, ssl)
    # Complete validation precedes either write; a changed supported file is never guessed at.
    if corrected_status != status:
        _write(status_path, corrected_status)
    if corrected_ssl != ssl:
        _write(ssl_path, corrected_ssl)


def _run(argv: list[str], *, payload: str | None = None, pass_fds: tuple[int, ...] = ()) -> str:
    result = subprocess.run(  # noqa: S603 -- Fixed executables; validated native values are argv, never shell.
        argv,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
        pass_fds=pass_fds,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode or len(result.stdout.encode()) > LIMIT:
        raise ValueError("Native hosting policy operation did not complete")
    return result.stdout.strip()


def _read(path: Path, *, limit: int = LIMIT) -> str:
    if path.resolve() != path:
        raise ValueError("Native policy evidence must not traverse symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, newline="") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Native evidence must be root-owned and protected")
        result = stream.read(limit + 1)
    if len(result.encode()) > limit:
        raise ValueError("Native policy evidence is oversized")
    return result


def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.resolve() != path.parent or path.parent.stat().st_uid != 0 or path.parent.stat().st_mode & 0o022:
        raise ValueError("Native policy state directory is not protected")
    fd, temporary = tempfile.mkstemp(prefix=".hosting-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


TUNNEL_ACCOUNT = "praho-webmin-tunnel"
_TUNNEL_HOME_CONTENT = frozenset({".ssh", ".ssh/authorized_keys", ".bashrc", ".profile", ".bash_logout"})


def tenant_homes(home: Path) -> list[str]:
    """Entries under /home other than PRAHO's own operator tunnel account (ADR-0060).

    The ssh-hardening role creates that system account before installation. Keep in step with the
    first-install guard in virtualmin.yml."""
    return sorted(entry.name for entry in home.iterdir() if not _own_tunnel_home(entry))


def _own_tunnel_home(entry: Path) -> bool:
    if entry.name != TUNNEL_ACCOUNT or entry.is_symlink() or not entry.is_dir():
        return False
    try:
        account = pwd.getpwnam(TUNNEL_ACCOUNT)
    except KeyError:
        return False
    # Only what the ssh-hardening role creates: the skeleton files and the enrolled operator keys.
    content = list(entry.rglob("*"))
    return (
        account.pw_dir == f"/home/{TUNNEL_ACCOUNT}"
        and account.pw_shell in {"/usr/sbin/nologin", "/sbin/nologin"}
        and entry.stat().st_uid == account.pw_uid
        and {str(item.relative_to(entry)) for item in content} <= _TUNNEL_HOME_CONTENT
        and not any(item.is_symlink() for item in content)
    )


def classic_bootstrap_allowed(inventory: dict[str, object]) -> bool:
    try:
        deployment = inventory["deployment"]
        if not isinstance(deployment, str) or not (
            re.fullmatch(r"[1-9][0-9]{0,18}", deployment) or str(UUID(deployment)) == deployment
        ):
            return False
        return (
            inventory.get("owned_new_deployment") is True
            and inventory.get("root_filesystem") is True
            and inventory.get("filesystem") == "ext4"
            and inventory.get("quota_format") == "none"
            and all(
                type(inventory.get(key)) is int and inventory[key] == 0
                for key in ("domains", "tenant_homes", "tenant_databases")
            )
        )
    except (KeyError, ValueError, TypeError):
        return False


def classic_fstab(contents: str) -> str:
    lines = contents.splitlines(keepends=True)
    roots = [
        (index, line.split())
        for index, line in enumerate(lines)
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line.split()) >= FSTAB_MIN_FIELDS
        and line.split()[1] == "/"
    ]
    if len(roots) != 1 or roots[0][1][2] != "ext4":
        raise ValueError("An unambiguous ext4 root filesystem is required")
    index, fields = roots[0]
    options = fields[3].split(",")
    if any(option.startswith(("usrjquota=", "grpjquota=", "jqfmt=")) for option in options):
        raise ValueError("Preserve the existing quota format and prepare it explicitly")
    fields[3] = ",".join(options + [name for name in ("usrquota", "grpquota") if name not in options])
    lines[index] = "\t".join(fields) + "\n"
    return "".join(lines)


def filesystem() -> dict[str, str]:
    rows = json.loads(_run(["/usr/bin/findmnt", "--json", "--target", "/", "--output", "SOURCE,FSTYPE,UUID,TARGET"]))[
        "filesystems"
    ]
    if len(rows) != 1:
        raise ValueError("The root filesystem is ambiguous")
    return rows[0]


def quota_format(device: str) -> str:
    features = _run(["/usr/sbin/tune2fs", "-l", device])
    rows = re.findall(r"^Filesystem features:\s*(.*)$", features, re.MULTILINE)
    if len(rows) != 1:
        raise ValueError("The ext4 quota format is unknown")
    if "quota" in rows[0].split():
        return "native"
    files = [Path("/aquota.user"), Path("/aquota.group")]
    if any(path.exists() for path in files):
        for path in files:
            if not path.exists():
                raise ValueError("Classic quota files are incomplete")
            _protected_file(path)
        return "classic"
    return "none"


def _protected_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Quota files must be protected root-owned regular files")


def qualification_inventory(
    proof: dict[str, object], *, installation: str, filesystem_uuid: str, boot: str
) -> dict[str, object]:
    """Historical destructive acceptance authorizes explicit recovery, never current-boot readiness."""
    if (
        set(proof) - set(QUALIFICATION_FIELDS) - {"qualification_id", "original_digest"}
        or set(QUALIFICATION_FIELDS) - set(proof)
        or proof.get("schema") != 1
        or type(proof.get("schema")) is not int
        or proof.get("policy_version") != "hosting-node-v1"
        or proof.get("installation") != installation
        or proof.get("filesystem_uuid") != filesystem_uuid
        or proof.get("os") != "ubuntu-26.04"
        or proof.get("php") != "8.5"
        or proof.get("filesystem") != "ext4"
        or proof.get("quota_format") not in {"native", "classic"}
        or any(
            proof.get(key) is not True
            for key in ("root_filesystem", "uid_enforced", "gid_enforced", "physical_tables_verified")
        )
        or any(proof.get(key) is not False for key in ("mysql_cap_sys_resource", "mysql_bounding_cap_sys_resource"))
        or not isinstance(proof.get("acceptance"), dict)
        or set(proof["acceptance"]) != set(ACCEPTANCE_CHECKS)
        or any(value is not True for value in proof["acceptance"].values())
    ):
        raise ValueError("Complete initial native acceptance for the same installation and filesystem is required")
    for value in (
        installation,
        filesystem_uuid,
        boot,
        proof["boot_id"],
        proof["acceptance_id"],
        proof.get("qualification_id", proof["acceptance_id"]),
    ):
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("Native qualification identity is malformed")
    return {
        **{key: proof[key] for key in QUALIFICATION_FIELDS},
        "boot_id": boot,
        "qualification_id": proof.get("qualification_id", proof["acceptance_id"]),
        "requalification_required": proof["boot_id"] != boot,
    }


def _reserved_probe_id() -> int:
    from praho_quota_native import _fields  # noqa: PLC0415 -- Only on qualified Ubuntu runtime.

    value = json.loads(_read(STATE / "probe-identity.json"))
    installation = (
        _read(INSTALLATION).strip() if INSTALLATION.exists() else str(UUID(_read(Path("/etc/machine-id")).strip()))
    )
    identifier = value.get("uid")
    if (
        set(value) != {"schema", "name", "uid", "gid", "state", "installation"}
        or value["schema"] != 1
        or type(value["schema"]) is not int
        or value["name"] != "praho-quota-probe"
        or type(identifier) is not int
        or not REQUALIFICATION_UID_MIN <= identifier < REQUALIFICATION_UID_MIN + REQUALIFICATION_UID_COUNT
        or value["gid"] != identifier
        or value["state"] != "reserved"
        or value["installation"] != installation
    ):
        raise ValueError("A protected exact reserved native probe identity is required")
    users, groups = pwd.getpwall(), grp.getgrall()
    user = [
        entry
        for entry in users
        if entry.pw_uid == identifier or entry.pw_name == "praho-quota-probe" or entry.pw_gid == identifier
    ]
    group = [entry for entry in groups if entry.gr_gid == identifier or entry.gr_name == "praho-quota-probe"]
    if (
        len(user) != 1
        or len(group) != 1
        or user[0].pw_name != value["name"]
        or group[0].gr_name != value["name"]
        or user[0].pw_uid != identifier
        or user[0].pw_gid != identifier
        or group[0].gr_gid != identifier
        or user[0].pw_gecos != "PRAHO isolated quota probe"
        or user[0].pw_dir != "/nonexistent"
        or user[0].pw_shell != "/usr/sbin/nologin"
        or group[0].gr_mem
        or Path("/nonexistent").exists()
    ):
        raise ValueError("Reserved native probe identity changed; retain the qualification hold")
    for path in Path("/etc/webmin/virtual-server/domains").iterdir():
        if path.name.isdigit():
            domain = _fields(path)
            if any(domain.get(key) == str(identifier) for key in ("uid", "gid", "ugid")):
                raise ValueError("A native domain references the isolated probe identity")
    return identifier


def _probe_cleanup(journal: dict[str, object], fs: dict[str, str]) -> None:
    from praho_quota_native import _kernel_quota, _set_kernel_quota  # noqa: PLC0415 -- Qualified fixed sibling ABI.

    identifier = journal.get("id")
    if (
        type(identifier) is not int
        or not REQUALIFICATION_UID_MIN <= identifier < REQUALIFICATION_UID_MIN + REQUALIFICATION_UID_COUNT
        or journal.get("filesystem_uuid") != fs["uuid"]
    ):
        raise ValueError("The isolated qualification cleanup identity changed")
    if identifier != _reserved_probe_id():
        raise ValueError("The isolated qualification identity no longer matches its protected reservation")
    base = REQUALIFICATION_ROOT
    if base.is_symlink() or (base.exists() and (base.stat().st_uid != 0 or base.stat().st_mode & 0o022)):
        raise ValueError("The isolated qualification parent is not protected")
    root = base / "writer"
    if root.exists():
        if root.is_symlink() or root.stat().st_uid not in {0, identifier}:
            raise ValueError("The isolated qualification path changed ownership")
        os.chown(root, 0, 0)
        target = root / "write.bin"
        if target.exists() or target.is_symlink():
            target.unlink()
        root.rmdir()  # An unknown file is never recursively removed.
    if base.exists():
        base.rmdir()
    for group in (False, True):
        _set_kernel_quota(fs["source"], identifier, 0, group=group)
        quota = _kernel_quota(fs["source"], identifier, group=group)
        if any((quota.hard, quota.soft, quota.space, quota.inodes, quota.inode_hard, quota.inode_soft)):
            raise ValueError("The isolated qualification probe was not fully cleaned up")
    (STATE / "requalification-probe.json").unlink(missing_ok=True)


def _isolated_requalification_probe(fs: dict[str, str], descriptor: int) -> None:
    """Bounded EDQUOT tests use an unused high identity; no tenant cap or data is touched."""
    from praho_quota_native import _kernel_quota, _set_kernel_quota  # noqa: PLC0415 -- Same synchronous kernel ABI.

    journal_path = STATE / "requalification-probe.json"
    if journal_path.exists():
        _probe_cleanup(json.loads(_read(journal_path)), fs)
    reserved = json.loads(_run(["/usr/bin/perl", str(PERL_ADAPTER), "reserve_probe"], pass_fds=(descriptor,)))
    provenance = STATE / "probe-identity.json"
    _write(provenance, _read(provenance))
    identifier = _reserved_probe_id()
    if reserved != {"uid": identifier, "gid": identifier}:
        raise ValueError("The native allocator returned a different reserved probe identity")
    quotas = [_kernel_quota(fs["source"], identifier, group=group) for group in (False, True)]
    if not all(not any((q.hard, q.soft, q.space, q.inodes, q.inode_hard, q.inode_soft)) for q in quotas):
        raise ValueError("Reserved probe identity has existing usage or caps; no tenant quantity was changed")
    journal = {"id": identifier, "filesystem_uuid": fs["uuid"]}
    base, root = REQUALIFICATION_ROOT, REQUALIFICATION_ROOT / "writer"
    if base.exists():
        raise ValueError("An unowned isolated qualification path requires operator review")
    _write(journal_path, json.dumps(journal))
    prefix = [
        "/usr/bin/setpriv",
        "--reuid",
        str(identifier),
        "--regid",
        str(identifier),
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
    ]
    python = """import errno,os,sys
try:
 with open(sys.argv[1],'wb',buffering=0) as stream:
  for _ in range(32): stream.write(b'x'*65536);os.fsync(stream.fileno())
except OSError as error:
 if error.errno != errno.EDQUOT: raise
 print(os.geteuid());sys.exit(0)
raise RuntimeError('The isolated writer did not encounter EDQUOT')
"""
    php = r"""$f=fopen($argv[1],'wb');$hit=false;for($i=0;$i<32;$i++){
$n=@fwrite($f,str_repeat('x',65536));if($n!==65536){$e=error_get_last();
$hit=(bool)preg_match('/(quota exceeded|errno=122)/i',$e['message']??'');break;}fflush($f);fsync($f);}
fclose($f);if(!$hit){fwrite(STDERR,'Isolated PHP writer did not encounter EDQUOT');exit(7);}echo posix_geteuid();"""
    try:
        base.mkdir(mode=0o711)
        root.mkdir(mode=0o700)
        os.chown(root, identifier, identifier)
        if root.stat().st_dev != Path("/").stat().st_dev:
            raise ValueError("The isolated probe is outside the qualified filesystem")
        for group, runtime in ((False, "python"), (True, "python"), (False, "php")):
            for quota_group in (False, True):
                _set_kernel_quota(
                    fs["source"],
                    identifier,
                    REQUALIFICATION_LIMIT_KIB if quota_group == group else 0,
                    group=quota_group,
                )
            argv = ["/usr/bin/python3", "-c", python] if runtime == "python" else ["/usr/bin/php8.5", "-r", php]
            if _run([*prefix, *argv, str(root / "write.bin")], pass_fds=(descriptor,)) != str(identifier):
                raise ValueError("The isolated denial proof used a different native identity")
            (root / "write.bin").unlink(missing_ok=True)
    finally:
        _probe_cleanup(journal, fs)


def _requalify_quota(identity: str, descriptor: int) -> None:
    # Both passive qualification and cleanup are completed under the native node
    # operation lock. A killed probe's inherited descriptor prevents early fencing.
    fs = filesystem()
    journal_path = STATE / "requalification-probe.json"
    if journal_path.exists():
        _probe_cleanup(json.loads(_read(journal_path)), fs)
    inventory = inspect(identity).get("quota", {})
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError("Inspect and qualify the same supported node before adoption")
    if not inventory["requalification_required"]:
        return
    original = _read(STATE / "native-acceptance.json")
    proof = json.loads(original)
    archive = STATE / "native-acceptance.initial.json"
    if not archive.exists():
        _write(archive, original)
    initial = _read(archive)
    initial_proof = json.loads(initial)
    if initial_proof["acceptance_id"] != proof["acceptance_id"]:
        raise ValueError("The original native acceptance provenance changed")
    _isolated_requalification_probe(fs, descriptor)
    fresh = inspect(identity).get("quota", {})
    if not isinstance(fresh, dict) or fresh.get("boot_id") != inventory["boot_id"]:
        raise ValueError("The node changed during isolated requalification")
    proof.update(
        boot_id=inventory["boot_id"],
        qualification_id=str(UUID(bytes=os.urandom(16))),
        original_digest=hashlib.sha256(initial.encode()).hexdigest(),
    )
    _write(STATE / "native-acceptance.json", json.dumps(proof, sort_keys=True))


def bootstrap(deployment: str) -> dict[str, object]:
    marker = json.loads(_read(STATE / "new-install.json"))
    fs = filesystem()
    device = fs.get("source", "")
    if not re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", device):
        raise ValueError("The ext4 root device is unsupported")
    domains = Path("/etc/webmin/virtual-server/domains")
    databases = _run(
        ["/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names", "--execute", "SHOW DATABASES"]
    )
    inventory = {
        "owned_new_deployment": marker == {"deployment": deployment, "owned_empty_first_install": True},
        "deployment": deployment,
        "domains": sum(1 for p in domains.iterdir() if p.name.isdigit()),
        "tenant_homes": len(tenant_homes(Path("/home"))),
        "tenant_databases": len(
            set(databases.splitlines()) - {"mysql", "sys", "information_schema", "performance_schema"}
        ),
        "filesystem": fs.get("fstype"),
        "root_filesystem": fs.get("target") == "/",
        "quota_format": quota_format(device),
    }
    if inventory["quota_format"] != "none":
        # Existing formats are never initialized, replaced or converted, even on a rerun.
        return {"prepared": False, "preserved_format": inventory["quota_format"]}
    if not classic_bootstrap_allowed(inventory):
        raise ValueError("Classic initialization is restricted to an owned empty first installation")
    fstab = Path("/etc/fstab")
    original = _read(fstab)
    _write(STATE / "fstab-before-classic", original)
    _write(fstab, classic_fstab(original))
    _run(["/usr/bin/mount", "-o", "remount", "/"])
    _run(["/usr/sbin/quotacheck", "-cugm", "/"])
    _run(["/usr/sbin/quotaon", "-ug", "/"])
    # Consumed before any later rerun can initialize again, regardless of a future tenant count.
    _write(STATE / "new-install.json", json.dumps({"deployment": deployment, "consumed": True}))
    return {"prepared": True, "preserved_format": "classic", "requires_native_acceptance": True}


def inspect(identity: str) -> dict[str, object]:  # noqa: C901 -- Keep fresh kernel, runtime, table and provenance checks in one fail-closed read boundary.
    installation = (
        _read(INSTALLATION).strip() if INSTALLATION.exists() else str(UUID(_read(Path("/etc/machine-id")).strip()))
    )
    if str(UUID(installation)) != installation:
        raise ValueError("Native installation identity is invalid")
    notifications = json.loads(_run(["/usr/bin/perl", str(PERL_ADAPTER), "inspect"]))
    os_quota_safe, os_quota_digest = os_quota_notification_inventory()
    notifications["evidence"]["emitters"]["os_quota_warnings"] = os_quota_safe
    guarded, source_digest = notification_guard_inventory()
    notifications["evidence"]["emitters"]["acme_owners"] = guarded
    notification_evidence = {
        "schema": 1,
        "policy_version": "hosting-node-v1",
        "identity": identity,
        "installation": installation,
        **notifications["evidence"],
    }
    result: dict[str, object] = {
        "identity": identity,
        "notifications": notification_evidence,
        "notification_inventory_digest": hashlib.sha256(
            json.dumps([notifications["inventory_digest"], os_quota_digest, source_digest]).encode()
        ).hexdigest(),
        "quota": {},
    }
    try:
        from praho_quota_native import (  # noqa: PLC0415 -- Root-owned sibling.
            NativeQuotaBackend,
            _database_writer_qualified,
            _fields,
        )

        proof = json.loads(_read(STATE / "native-acceptance.json"))
        fs = filesystem()
        if fs.get("fstype") != "ext4" or fs.get("target") != "/":
            raise ValueError("The managed root filesystem no longer matches the qualified layout")
        for kind, flag in (("user", "-u"), ("group", "-g")):
            enabled = _run(["/usr/sbin/quotaon", "-p", flag, "/"])
            if re.fullmatch(kind + r" quota on [^\r\n]+ is on", enabled) is None:
                raise ValueError("Both kernel quota classes must remain active")
        boot = _read(Path("/proc/sys/kernel/random/boot_id")).strip()
        if (
            proof["installation"] != installation
            or proof["filesystem_uuid"] != fs["uuid"]
            or proof["os"] != "ubuntu-26.04"
            or proof["php"] != "8.5"
        ):
            raise ValueError("Native acceptance needs a fresh reboot/update proof")
        qualified = qualification_inventory(proof, installation=installation, filesystem_uuid=fs["uuid"], boot=boot)
        if (
            "original_digest" in proof
            and hashlib.sha256(_read(STATE / "native-acceptance.initial.json").encode()).hexdigest()
            != proof["original_digest"]
        ):
            raise ValueError("The original native acceptance provenance changed")
        os_release = dict(line.split("=", 1) for line in _read(Path("/usr/lib/os-release")).splitlines() if "=" in line)
        if os_release.get("ID", "").strip('"') != "ubuntu" or os_release.get("VERSION_ID", "").strip('"') != "26.04":
            raise ValueError("Unsupported managed node baseline")
        if _run(["/usr/bin/php8.5", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"]) != "8.5":
            raise ValueError("Unsupported managed PHP baseline")
        _database_writer_qualified()
        for path in Path("/etc/webmin/virtual-server/domains").iterdir():
            if not path.name.isdigit():
                continue
            domain = _fields(path)
            if domain.get("alias"):
                continue
            NativeQuotaBackend().probe(
                {
                    "identity": {
                        "installation": installation,
                        "domain_id": path.name,
                        "domain": domain["dom"],
                        "uid": int(domain["uid"]),
                        "gid": int(domain["gid"]),
                        "filesystem_uuid": fs["uuid"],
                        "boot_id": boot,
                    }
                }
            )
        result["quota"] = {
            **qualified,
            "identity": identity,
            "quota_format": quota_format(fs["source"]),
            "bw_auto_disable": notifications["bandwidth_policy"]["auto_disable"],
            "bw_auto_enable": notifications["bandwidth_policy"]["auto_enable"],
        }
    except (ImportError, OSError, ValueError, KeyError):
        result["quota_refusal"] = "Native quota acceptance is missing, changed or unsupported"
    return result


def native_emitter_command(command: bytes) -> bool:
    # The persistent lookup daemon only returns mailbox/quota metadata, flushes
    # native caches per request, and never sends notifications. It must keep
    # serving retained mail throughout policy changes.
    return any(
        (
            argument.startswith(b"/usr/share/webmin/virtual-server/")
            and argument != b"/usr/share/webmin/virtual-server/lookup-domain-daemon.pl"
        )
        or argument in {b"/usr/share/webmin/status/monitor.pl", b"/usr/sbin/virtualmin", b"/usr/sbin/warnquota"}
        for argument in command.split(b"\0")
    )


def _emitters_idle() -> None:
    deadline, poll = monotonic() + 15, Event()
    while True:
        active = False
        for process in Path("/proc").iterdir():
            if not process.name.isdigit() or int(process.name) == os.getpid():
                continue
            try:
                command = (process / "cmdline").read_bytes()[:8192]
            except (FileNotFoundError, ProcessLookupError):
                continue
            if native_emitter_command(command):
                active = True
                break
        if not active:
            return
        if monotonic() >= deadline:
            raise ValueError("A native customer emitter may still hold old settings; reconcile after it exits")
        poll.wait(0.2)


def _notification_apply(request: dict[str, object], descriptor: int, *, replace: bool) -> None:
    if not os_quota_notification_inventory()[0]:
        raise ValueError("Review the OS quota warning route before handing customer notifications to Platform")
    operators = request.get("operator_emails", [])
    if (
        not isinstance(operators, list)
        or len(operators) > MAX_OPERATOR_EMAILS
        or any(not isinstance(value, str) or "\n" in value or "\r" in value for value in operators)
    ):
        raise ValueError("Explicit approved operator recipient authority is required")
    _apply_notification_source_patches()
    _run(
        ["/usr/bin/perl", str(PERL_ADAPTER), "apply"],
        payload=json.dumps({"operator_emails": operators, "replace_authority": replace}),
        pass_fds=(descriptor,),
    )
    # Persist the accepted operator authority through a reboot before reporting handover.
    operators_file = STATE / "operators.json"
    _write(operators_file, _read(operators_file))
    _run(["/usr/bin/systemctl", "restart", "webmin"], pass_fds=(descriptor,))
    _emitters_idle()


def perform(action: str, request: dict[str, object]) -> dict[str, object]:  # noqa: C901, PLR0912 -- Fixed read/bootstrap/recovery/token phases share one native operation mutex.
    identity = request.get("identity")
    if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise ValueError("An exact Platform connection identity is required")
    if action == "inspect":
        return inspect(identity)
    if action == "bootstrap":
        return bootstrap(str(request.get("deployment", "")))
    token = request.get("token")
    if action != "reconcile" and (
        not isinstance(token, str)
        or str(UUID(token)) != token
        or action not in {"handover", "fence", "quota_policy", "quota_fence", "requalify", "requalify_fence"}
    ):
        raise ValueError("A fixed admitted native handover token is required")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(STATE / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == "reconcile":
            if _read(STATE / "notification-owner").strip() != "platform":
                raise ValueError("Reconciliation requires an explicit existing Platform mail handover")
            _notification_apply(request, lock, replace=False)
            return inspect(identity)
        if not isinstance(token, str):
            raise ValueError("An exact token is required")
        cancelled = STATE / ("cancelled-" + token)
        if action in {"fence", "quota_fence", "requalify_fence"}:
            # A stopped, permanently fenced old token cannot reapply after this exact repair.
            _write(cancelled, token)
        if action in {"handover", "quota_policy", "requalify"}:
            if cancelled.exists():
                raise ValueError("This handover token was permanently fenced")
            _write(
                STATE / "running.json",
                json.dumps(
                    {"token": token, "digest": hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()}
                ),
            )
        if action in {"quota_policy", "quota_fence"}:
            # Native warning ownership and schedules remain unchanged at quota adoption.
            _requalify_quota(identity, lock)
            _run(["/usr/bin/perl", str(PERL_ADAPTER), "resource"], pass_fds=(lock,))
            _run(["/usr/bin/systemctl", "restart", "webmin"], pass_fds=(lock,))
            _emitters_idle()
            _write(STATE / "resource-policy", "no-native-bandwidth-actions-v1\n")
        elif action in {"requalify", "requalify_fence"}:
            # Existing parent holds remain authoritative. This path never edits
            # tenant/domain/BW state or restarts panel/MTA services.
            _requalify_quota(identity, lock)
        else:
            # Initial handover and approved recovery apply the same accepted operator authority.
            _notification_apply(request, lock, replace=True)
            _write(STATE / "notification-owner", "platform\n")
        # Fence after synchronous completion before returning. A delayed duplicate cannot reapply.
        _write(cancelled, token)
        return {**inspect(identity), "fenced_token": token}
    finally:
        os.close(lock)


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != COMMAND_ARGUMENTS:
        raise ValueError("A root-owned hosting policy operation is required")
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Hosting policy request exceeds its bound")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("Hosting policy request must be a JSON object")

    def deadline(_signum: int, _frame: object) -> None:
        raise TimeoutError("Native node hosting operation exceeded its bounded deadline")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(150)
    print(json.dumps(perform(sys.argv[1], request), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
