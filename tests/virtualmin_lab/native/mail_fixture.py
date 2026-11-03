#!/usr/bin/env python3
"""Dedicated pinned full-mail userspace fixture; never a kernel quota proof.

All actions require a private exact manifest and task labels. Existing lab
containers are never started, enrolled, modified or removed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[3]
TASK = "hosting-776-mail"
IMAGE = "praho-virtualmin-lab-mixed-source:8.3.0"


def command(argv: list[str], *, payload: str | None = None, timeout: int = 30) -> str:
    result = subprocess.run(argv, input=payload, text=True, capture_output=True, check=False, timeout=timeout)  # noqa: S603 -- Fixed Docker argv and exact fixture identities.
    if result.returncode:
        raise AssertionError(result.stderr[-2000:])
    return result.stdout.strip()


def save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def read(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("A private owned mail fixture manifest is required")
    value = json.loads(path.read_text())
    if value["task"] != TASK or str(UUID(value["run"])) != value["run"]:
        raise ValueError("This is not the dedicated native-mail fixture")
    return value


def owned(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    value = read(path)
    identifier = value.get("container")
    if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
        raise ValueError("The exact owned container identity is unknown; reconcile its task label first")
    result = json.loads(command(["docker", "inspect", identifier]))[0]
    labels = result["Config"]["Labels"]
    if (
        result["Id"] != identifier
        or labels.get("praho.task") != TASK
        or labels.get("praho.run") != value["run"]
        or result["Image"] != value["image"]
    ):
        raise ValueError("Native mail fixture ownership changed")
    return value, result


def create(path: Path) -> None:
    if path.exists():
        raise ValueError("A manifest already exists; inspect or clean up that exact fixture first")
    image = json.loads(command(["docker", "image", "inspect", IMAGE]))[0]
    if (
        image["Config"]["Labels"].get("io.virtualmin.webmin.version") != "2.670"
        or image["Config"]["Labels"].get("io.virtualmin.virtual-server.version") != "8.3.0-1-gpl"
    ):
        raise ValueError("Build the pinned full-mail fixture image before native notification tests")
    value = {
        "task": TASK,
        "run": str(uuid4()),
        "image": image["Id"],
        "container": None,
        "phase": "creating",
        "expires_at": (datetime.now(UTC) + timedelta(hours=4)).isoformat(),
    }
    save(path, value)
    cid = command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            "praho-mail-" + value["run"],
            "--label",
            "praho.task=" + TASK,
            "--label",
            "praho.run=" + value["run"],
            "--label",
            "com.docker.compose.project=praho-hosting-776-mail",
            "--label",
            "com.docker.compose.service=native-mail",
            "--hostname",
            "mail-fixture.praho.test",
            "--privileged",
            "--cgroupns=host",
            "--memory",
            "2g",
            "--cpus",
            "2",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--mount",
            "type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup",
            image["Id"],
        ],
        timeout=60,
    )
    if re.fullmatch(r"[0-9a-f]{64}", cid) is None:
        raise ValueError("Docker returned an ambiguous native fixture identity")
    value["container"], value["phase"] = cid, "booting"
    save(path, value)
    print("Task-owned native-mail fixture: " + cid, flush=True)
    deadline, poll = monotonic() + 900, Event()
    while True:
        _value, current = owned(path)
        if current["State"].get("Health", {}).get("Status") == "healthy":
            break
        if monotonic() >= deadline or not current["State"]["Running"]:
            raise AssertionError("Pinned full-mail fixture did not become healthy; exact resource retained")
        poll.wait(2)
    value["phase"] = "ready"
    save(path, value)
    print("Pinned full-mail fixture ready; no existing lab container was changed", flush=True)


def verify(path: Path) -> None:
    value, current = owned(path)
    if not current["State"]["Running"] or datetime.now(UTC) >= datetime.fromisoformat(value["expires_at"]):
        raise ValueError("The exact native mail fixture must be running and unexpired")
    cid = value["container"]
    command(
        [
            "docker",
            "exec",
            cid,
            "mkdir",
            "-p",
            "/root/praho-native-mail",
            "/usr/local/lib/praho",
            "/var/lib/praho/hosting",
        ]
    )
    source = ROOT / "services/platform/infrastructure/ansible/playbooks/files"
    for name in (
        "praho_quota.py",
        "praho_quota_native.py",
        "praho_usage.py",
        "praho-quota-metadata.pl",
        "praho_hosting_node.py",
        "praho-notification-policy.pl",
    ):
        command(["docker", "cp", str(source / name), cid + ":/usr/local/lib/praho/" + name])
    for filename, target in (
        (Path(__file__).with_name("mail_acceptance.py"), "mail_acceptance.py"),
        (ROOT / "tests/virtualmin_lab/components/retained_probe.py", "retained_probe.py"),
    ):
        command(["docker", "cp", str(filename), cid + ":/root/praho-native-mail/" + target])
    result = command(
        ["docker", "exec", "-i", cid, "/usr/bin/python3", "/root/praho-native-mail/mail_acceptance.py"],
        payload=json.dumps({"run": value["run"], "post_handover": value["phase"] == "verified"}),
        timeout=900,
    )
    proof = {**value.get("proof", {}), **json.loads(result)}
    if (
        proof.get("native_customer_attempts") != 0
        or proof.get("operator_attempts", 0) < 1
        or not proof.get("retained_mail")
    ):
        raise AssertionError("Native mail ownership did not satisfy customer and retained operator/mail controls")
    value["phase"], value["proof"] = "verified", proof
    save(path, value)
    print(json.dumps(proof, sort_keys=True))


def destroy(path: Path) -> None:
    value, current = owned(path)
    if current.get("ExecIDs"):
        raise ValueError("Native fixture still has active exec sessions; finish them before cleanup")
    if current["State"]["Running"]:
        command(["docker", "stop", "--time", "30", value["container"]], timeout=45)
    _value, stopped = owned(path)
    if stopped["State"]["Running"] or stopped.get("ExecIDs"):
        raise ValueError("Native fixture did not stop cleanly; exact resource retained")
    command(["docker", "rm", value["container"]])
    value["phase"] = "destroyed"
    save(path, value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify", "destroy"))
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    {"create": create, "verify": verify, "destroy": destroy}[args.action](args.manifest)


if __name__ == "__main__":
    main()
