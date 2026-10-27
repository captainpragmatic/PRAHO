#!/usr/bin/env python3
"""Native unit pre-start guard: a crashed setup never starts package-default mail."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROFILES = frozenset({"debian12-dovecot23", "ubuntu2604-dovecot24"})
START_TICK_INDEX = 19
CHAIN = "PRAHO_MAIL_SETUP"
PORTS = "25,110,143,465,587,993,995"


def execute(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, timeout=10)  # noqa: S603


def configured(marker: dict[str, Any]) -> bool:
    spec = importlib.util.spec_from_file_location("praho_mail_node", Path(__file__).with_name("praho-mail.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    node = module.MailNode()
    expected = marker["node"]
    node.profile(expected)
    setup = node.setup_driver()
    setup.security_configuration(expected)
    # Verify the actual owned server certificate, rather than the later Webmin source file.
    execute(setup.certificate_verify_command(expected, Path("/etc/praho-mail/node.pem")))
    return True


class MailBootGuard:
    def __init__(
        self,
        root: Path = Path("/"),
        *,
        execute: Callable[[list[str]], None] = execute,
        configured: Callable[[dict[str, Any]], bool] = configured,
    ) -> None:
        self.root = root
        self.execute = execute
        self.configured = configured

    def allowed(self) -> bool:
        try:
            file = self.root / "var/lib/praho/mail/node.json"
            if file.is_symlink() or file.stat().st_uid != os.geteuid() or file.stat().st_mode & 0o022:
                return False
            marker = json.loads(file.read_text())
            if marker.get("version") != 1 or marker.get("profile") not in PROFILES:
                return False
            if marker.get("status") == "ready":
                return self.configured(marker)
            if not self.live_setup(marker):
                return False
            for program in ("iptables", "ip6tables"):
                self.execute([program, "-w", "5", "-C", "INPUT", "-j", CHAIN])
                self.execute(
                    [program, "-w", "5", "-C", CHAIN, "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "REJECT"]
                )
            return True
        except Exception:
            return False

    def live_setup(self, marker: dict[str, Any]) -> bool:
        if marker.get("status") != "applying" or marker.get("fenced") is not True:
            return False
        if type(marker.get("pid")) is not int or marker["pid"] <= 1:
            return False
        if (self.root / "proc/sys/kernel/random/boot_id").read_text().strip() != marker.get("boot_id"):
            return False
        stat = (self.root / f"proc/{marker['pid']}/stat").read_text().rpartition(") ")[2].split()
        return len(stat) > START_TICK_INDEX and stat[START_TICK_INDEX] == marker.get("start_tick")


if __name__ == "__main__":
    if os.geteuid() != 0 or not MailBootGuard().allowed():
        print("mail_startup_unproven", file=sys.stderr)
        raise SystemExit(1)
