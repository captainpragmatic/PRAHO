"""Refuse SSH policy adoption when a full baseline would erase custom access rules."""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

# These are the stock Ubuntu directives and settings already owned by PRAHO's
# previous SSH playbooks. Everything else needs explicit operator review.
SUPPORTED = frozenset(
    [
        "port",
        "permitrootlogin",
        "pubkeyauthentication",
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "challengeresponseauthentication",
        "authenticationmethods",
        "permitemptypasswords",
        "usepam",
        "usedns",
        "maxauthtries",
        "maxsessions",
        "logingracetime",
        "strictmodes",
        "printmotd",
        "printlastlog",
        "acceptenv",
        "x11forwarding",
        "allowtcpforwarding",
        "allowagentforwarding",
        "clientaliveinterval",
        "clientalivecountmax",
        "protocol",
        "ciphers",
        "macs",
        "kexalgorithms",
        "hostbasedauthentication",
        "ignorerhosts",
        "permituserenvironment",
        "loglevel",
        "maxstartups",
        "permittunnel",
        "gatewayports",
        "tcpkeepalive",
    ]
)


def validate(config: Path, *, snippets: Path | None = None) -> None:
    """Read only. A single conventional include is allowed, with no nested includes."""
    for raw in config.read_text().splitlines():
        words = shlex.split(raw, comments=True)
        if not words:
            continue
        directive, *values = words
        directive = directive.lower()
        if directive == "include" and values == ["/etc/ssh/sshd_config.d/*.conf"] and snippets is not None:
            for fragment in sorted(snippets.glob("*.conf")):
                validate(fragment)
        elif (
            directive == "authorizedkeysfile"
            and values in ([".ssh/authorized_keys"], [".ssh/authorized_keys", ".ssh/authorized_keys2"])
        ) or (
            directive == "subsystem" and values in (["sftp", "/usr/lib/openssh/sftp-server"], ["sftp", "internal-sftp"])
        ):
            continue
        elif directive not in SUPPORTED or not values:
            raise ValueError(f"custom SSH policy in {config.name}: {directive}; review before adoption")


def validate_startup(properties: dict[str, str], options: str) -> None:
    """Accept the vendor ssh.service with an explicitly empty SSHD_OPTS only."""
    expected = {
        "FragmentPath": {"/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service"},
        "KillMode": {"process"},
        "DropInPaths": {""},
        "Environment": {""},
        "EnvironmentFiles": {"/etc/default/ssh (ignore_errors=yes)"},
    }
    if any(properties.get(key) not in values for key, values in expected.items()):
        raise ValueError("custom SSH service policy; review before adoption")
    if not re.match(
        r"^\{ path=/usr/sbin/sshd ; argv\[\]=/usr/sbin/sshd -D \$SSHD_OPTS ; ignore_errors=no ;",
        properties.get("ExecStart", ""),
    ):
        raise ValueError("custom SSH service command; review before adoption")
    assignments = [
        line.strip() for line in options.splitlines() if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]
    if not assignments or any(not re.fullmatch(r"""SSHD_OPTS\s*=\s*(?:""|'')?\s*""", line) for line in assignments):
        raise ValueError("custom SSHD_OPTS; review before adoption")


if __name__ == "__main__":
    try:
        path = Path(sys.argv[1])
        validate(path, snippets=path.parent / "sshd_config.d")
        if "--check-service" in sys.argv:
            properties = subprocess.check_output(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--property=FragmentPath,KillMode,DropInPaths,Environment,EnvironmentFiles,ExecStart",
                    "ssh.service",
                ],
                text=True,
                timeout=10,
            )
            validate_startup(
                dict(line.split("=", 1) for line in properties.splitlines()), Path("/etc/default/ssh").read_text()
            )
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
