"""Fixed root-only checks for a disposable mail test node; never an application command API.

The dispatcher deliberately catches command failures/timeouts without printing argv,
stdout, stderr, secrets or a traceback. Full diagnostic journals stay inside the clone.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import imaplib
import json
import os
import poplib
import pwd
import re
import secrets
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

PROTECTED = (
    "/etc/pam.d/sshd",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-session",
    "/etc/ssh/sshd_config",
)
PERMITTED = {
    "virtual-server": {"mail", "mail_system", "last_check", "last_letsencrypt_mass_renewal"},
    "mailboxes": {"mail_system"},
}


class CheckError(RuntimeError):
    pass


def command(argv: list[str], *, data: str | None = None, timeout: int = 180) -> str:
    try:
        result = subprocess.run(argv, input=data, text=True, capture_output=True, check=False, timeout=timeout)  # noqa: S603 -- fixed dispatcher commands
    except (subprocess.SubprocessError, OSError):
        raise CheckError("fixed_command_failed") from None
    if result.returncode:
        raise CheckError("fixed_command_refused")
    return result.stdout


def save(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


def inventory(directory: Path) -> list[dict[str, Any]]:
    result = json.loads(
        command(["perl", str(directory / "praho-mail-native.pl")], data=json.dumps({"action": "inventory"}))
    )
    if result.get("error") or not isinstance(result.get("domains"), list):
        raise CheckError("native_inventory_failed")
    return sorted(result["domains"], key=lambda row: row["domain"])


def profile(_request: dict[str, Any], directory: Path) -> dict[str, Any]:
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    return {
        "os_id": release["ID"].strip('"'),
        "os_version": release["VERSION_ID"].strip('"'),
        "virtualmin": command(["dpkg-query", "--show", "--showformat=${Version}", "webmin-virtual-server"]).strip(),
        "domain_count": len(inventory(directory)),
    }


def config_hashes() -> dict[str, dict[str, str]]:
    return {
        module: {
            line.partition("=")[0]: hashlib.sha256(line.partition("=")[2].encode()).hexdigest()
            for line in Path("/etc/webmin", module, "config").read_text().splitlines()
            if "=" in line and line.partition("=")[0] not in permitted
        }
        for module, permitted in PERMITTED.items()
    }


def snapshot(directory: Path) -> dict[str, Any]:
    users = {row.pw_name for row in pwd.getpwall() if row.pw_uid == 0 or row.pw_uid >= 1000}
    shadow = {
        row.partition(":")[0]: hashlib.sha256(row.encode()).hexdigest()
        for row in Path("/etc/shadow").read_text().splitlines()
        if row.partition(":")[0] in users
    }
    protected = {}
    for filename in PROTECTED:
        path = Path(filename)
        if path.is_file():
            protected[filename] = [hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o777]
    return {"shadow": shadow, "protected": protected, "providers": config_hashes(), "domains": inventory(directory)}


def create_domain(directory: Path, *, suffix: str, defaults: bool) -> dict[str, str]:
    identifier = directory.name[:8]
    record = {
        "domain": f"{suffix}-{identifier}.mail-lab.praho.test",
        "owner": suffix[:5] + identifier,
        "password": secrets.token_urlsafe(32),
    }
    features = ["--default-features"] if defaults else ["--dir", "--web", "--ssl", "--unix"]
    command(
        [
            "virtualmin",
            "create-domain",
            "--domain",
            record["domain"],
            "--user",
            record["owner"],
            "--pass",
            record["password"],
            *features,
        ]
    )
    save(directory / (suffix + ".json"), json.dumps(record))
    return record


def prepare(request: dict[str, Any], directory: Path) -> dict[str, Any]:
    material = request["material"]
    save(Path("/etc/webmin/miniserv.pem"), material["pem"])
    ca = Path("/usr/local/share/ca-certificates/praho-mail-lab-" + directory.name + ".crt")
    save(ca, material["ca"])
    command(["update-ca-certificates"], timeout=180)
    config = Path("/etc/webmin/miniserv.conf")
    lines = [
        line for line in config.read_text().splitlines() if not line.startswith(("keyfile=", "certfile=", "extracas="))
    ]
    save(config, "\n".join([*lines, "keyfile=/etc/webmin/miniserv.pem"]) + "\n")
    # Representative opaque provider keys ensure preservation is not vacuously checked on an empty configuration.
    provider = Path("/etc/webmin/virtual-server/config")
    save(
        provider,
        provider.read_text()
        + "\ncloudflare_mail_lab_key="
        + secrets.token_hex(24)
        + "\ndns_mail_lab_key="
        + secrets.token_hex(24)
        + "\n",
    )
    existing = create_domain(directory, suffix="existing", defaults=False)
    command(["chage", "-m", "2", "-M", "120", "-W", "10", "-I", "14", existing["owner"]])
    save(directory / "baseline.json", json.dumps(snapshot(directory)))
    # /run is a tmpfs. Its disappearance proves the later Docker restart recreated the node runtime.
    save(Path("/run/praho-mail-lab-" + directory.name), "before-restart")
    return {"fixture_prepared": True}


def preserved(_request: dict[str, Any], directory: Path) -> dict[str, Any]:
    before, after = json.loads((directory / "baseline.json").read_text()), snapshot(directory)
    facts = {
        "global_auth_unchanged": before["protected"] == after["protected"],
        "existing_credentials_and_aging_unchanged": all(
            after["shadow"].get(name) == value for name, value in before["shadow"].items()
        ),
        "provider_configuration_unchanged": before["providers"] == after["providers"],
        "existing_mail_flags_unchanged": all(row in after["domains"] for row in before["domains"]),
    }
    if not all(facts.values()):
        raise CheckError("preservation_failed")
    return facts


def new_default(_request: dict[str, Any], directory: Path) -> dict[str, Any]:
    record = create_domain(directory, suffix="fresh", defaults=True)
    rows = [row for row in inventory(directory) if row["domain"] == record["domain"]]
    if len(rows) != 1 or rows[0].get("mail_enabled") is not False:
        raise CheckError("new_domain_mail_not_off")
    return {"new_default_feature_account_mail_off": True}


def unix_control(owner: str, password: str) -> None:
    row = next(
        line.split(":") for line in Path("/etc/shadow").read_text().splitlines() if line.partition(":")[0] == owner
    )
    today = int(time.time() // 86400)
    if (
        row[1].startswith(("!", "*"))
        or int(row[2]) <= 0
        or (row[4] and int(row[4]) >= 0 and today > int(row[2]) + int(row[4]))
        or (row[7] and int(row[7]) >= 0 and today >= int(row[7]))
    ):
        raise CheckError("unix_control_not_active")
    library = ctypes.CDLL(ctypes.util.find_library("crypt"))
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p
    if library.crypt(password.encode(), row[1].encode()) != row[1].encode():
        raise CheckError("unix_control_password_invalid")


def assert_denied(authenticate: Callable[[], object], expected: type[Exception]) -> None:
    try:
        authenticate()
    except expected:
        return
    raise CheckError("unenrolled_mail_login_accepted")


def pop_login(client: poplib.POP3_SSL, owner: str, password: str) -> object:
    client.user(owner)
    return client.pass_(password)


def denied(request: dict[str, Any], directory: Path) -> dict[str, Any]:
    hostname = request["hostname"]
    context = ssl.create_default_context()

    def connection(port: int) -> ssl.SSLSocket:
        return context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=25), server_hostname=hostname)

    class IMAP(imaplib.IMAP4_SSL):
        def _create_socket(self, timeout):
            return connection(993)

    class POP(poplib.POP3_SSL):
        def _create_socket(self, timeout):
            return connection(995)

    class SMTP(smtplib.SMTP_SSL):
        def _get_socket(self, host, port, timeout):
            return connection(465)

    checked = 0
    for name in ("existing", "fresh"):
        path = directory / (name + ".json")
        if not path.exists():
            continue
        record = json.loads(path.read_text())
        owner, password = record["owner"], record["password"]
        unix_control(owner, password)
        imap = IMAP(hostname, 993, ssl_context=context, timeout=25)
        try:
            assert_denied(partial(imap.login, owner, password), imaplib.IMAP4.error)
        finally:
            imap.logout()
        pop = POP(hostname, 995, context=context, timeout=25)
        try:
            assert_denied(partial(pop_login, pop, owner, password), poplib.error_proto)
        finally:
            pop.close()
        smtp = SMTP(hostname, 465, context=context, timeout=25)
        try:
            assert_denied(partial(smtp.login, owner, password), smtplib.SMTPAuthenticationError)
        finally:
            smtp.close()
        checked += 1
    if checked == 0:
        raise CheckError("missing_unix_control")
    return {"verified_tls_and_valid_unix_controls": checked, "unenrolled_denied_993_995_465": True}


def boot_state(_request: dict[str, Any], directory: Path) -> dict[str, Any]:
    if Path("/run/praho-mail-lab-" + directory.name).exists():
        raise CheckError("runtime_not_recreated")
    command(["systemctl", "is-active", "postfix", "dovecot", "cron"], timeout=30)
    state = json.loads(Path("/var/lib/praho/mail/node.json").read_text())
    if state.get("status") != "ready":
        raise CheckError("persistent_mail_journal_not_ready")
    return {"runtime_recreated": True, "mail_services_active": True, "persistent_mail_journal_ready": True}


def main() -> int:
    action = "invalid"
    try:
        request = json.loads(sys.stdin.read(65537))
        run_id = request["run_id"]
        if os.geteuid() != 0 or not isinstance(run_id, str) or re.fullmatch(r"[a-f0-9]{32}", run_id) is None:
            raise CheckError("invalid_test_identity")
        directory = Path("/var/lib/praho-mail-lab", run_id)
        if directory.resolve() != Path(__file__).resolve().parent or directory.stat().st_mode & 0o077:
            raise CheckError("invalid_private_test_directory")
        actions = {
            "profile": profile,
            "prepare": prepare,
            "preserved": preserved,
            "new_default": new_default,
            "denied": denied,
            "boot_state": boot_state,
        }
        action = request.get("action", "invalid")
        if action not in actions:
            raise CheckError("unknown_fixed_action")
        result = actions[action](request, directory)
        print(json.dumps({"ok": True, **result}))
        return 0
    except Exception:
        # Never include exception text/tracebacks: native create argv contains an ephemeral test password.
        print(
            json.dumps(
                {
                    "ok": False,
                    "code": "mail_lab_node_check_failed",
                    "stage": action
                    if action in {"profile", "prepare", "preserved", "new_default", "denied", "boot_state"}
                    else "invalid",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
