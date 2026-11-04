"""Private loopback-only storage for one manifest-owned disposable native run.

This supplies real SSE-S3 backup storage, not native kernel or VM proof. No
shared lab container or customer bucket is used, and cleanup checks exact IDs.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import secrets
import stat
import subprocess
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any
from uuid import UUID

IMAGE = "cgr.dev/chainguard/minio@sha256:dc455cdd4db6e390b1b26514f15ff37681a777bf8dab41aac445a0259f751e56"
OWNER = "praho-native-storage-776"


def command(arguments: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=timeout)  # noqa: S603 -- Fixed Docker CLI and task-owned exact identity.
    if result.returncode:
        raise ValueError("Disposable native storage command failed; inspect the exact owned container")
    return result.stdout.strip()


def private_json(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
        or info.st_size > 65536
    ):
        raise ValueError("A bounded private owned manifest is required")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("The native storage manifest is invalid")
    return value


def write_private(path: Path, value: str, *, exclusive: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def manifest_run(path: Path) -> str:
    # Reuse the provider's exact file/owner/schema validation without invoking
    # its client or exposing any provider credentials to this local fixture.
    spec = importlib.util.spec_from_file_location("praho_native_provider", Path(__file__).with_name("provider_vm.py"))
    if spec is None or spec.loader is None:
        raise ValueError("The native provider manifest validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.read_manifest(path)["run"])


def read_fixture(path: Path) -> dict[str, Any]:
    value = private_json(path)
    if (
        value.get("schema") != 1
        or value.get("owner") != OWNER
        or str(UUID(value.get("run", ""))) != value["run"]
        or value.get("bucket") != "praho-native-" + value["run"]
    ):
        raise ValueError("The storage fixture is not owned by this native test run")
    return value


def owned_container(value: dict[str, Any]) -> dict[str, Any]:
    cid = value.get("container_id", "")
    if not isinstance(cid, str) or len(cid) != 64 or any(char not in "0123456789abcdef" for char in cid):
        raise ValueError("An exact recorded disposable storage container is required")
    container = json.loads(command(["docker", "inspect", cid]))[0]
    labels = container["Config"].get("Labels") or {}
    if (
        container["Id"] != cid
        or labels.get("praho.native.owner") != OWNER
        or labels.get("praho.native.run") != value["run"]
    ):
        raise ValueError("The storage container is outside the native fixture's authority")
    return container


def storage_client(value: dict[str, Any]) -> Any:
    import boto3  # noqa: PLC0415 -- Real S3 boundary only for explicit fixture actions.
    from botocore.config import Config  # noqa: PLC0415

    return boto3.client(
        "s3",
        endpoint_url=value["endpoint"],
        region_name="us-east-1",
        aws_access_key_id=value["access_key"],
        aws_secret_access_key=value["secret_key"],
        config=Config(s3={"addressing_style": "path"}, connect_timeout=2, read_timeout=5, retries={"max_attempts": 0}),
    )


def create(path: Path, *, run: str) -> None:
    run = str(UUID(run))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = path.with_suffix(path.suffix + ".env")
    if path.exists() or environment.exists():
        raise ValueError("Native storage fixture already exists; verify or clean up its exact recorded identity")
    value = {
        "schema": 1,
        "owner": OWNER,
        "run": run,
        "bucket": "praho-native-" + run,
        "access_key": "native-" + secrets.token_hex(8),
        "secret_key": secrets.token_urlsafe(32),
        "container_id": None,
    }
    write_private(path, json.dumps(value), exclusive=True)
    write_private(
        environment,
        "MINIO_ROOT_USER="
        + value["access_key"]
        + "\nMINIO_ROOT_PASSWORD="
        + value["secret_key"]
        + "\nMINIO_KMS_SECRET_KEY=native-key:"
        + base64.b64encode(secrets.token_bytes(32)).decode()
        + "\n",
        exclusive=True,
    )
    cid = command(
        [
            "docker",
            "create",
            "--label",
            "praho.native.owner=" + OWNER,
            "--label",
            "praho.native.run=" + run,
            "--publish",
            "127.0.0.1::9000",
            "--tmpfs",
            "/data:uid=65532,gid=65532",
            "--env-file",
            str(environment),
            IMAGE,
            "server",
            "/data",
            "--address",
            ":9000",
        ],
        timeout=180,
    )
    value["container_id"] = cid
    write_private(path, json.dumps(value))
    command(["docker", "start", cid])
    container = owned_container(value)
    ports = container["NetworkSettings"]["Ports"]["9000/tcp"]
    if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
        raise ValueError("Native storage must remain bound only to loopback")
    value["endpoint"] = "http://127.0.0.1:" + ports[0]["HostPort"]
    write_private(path, json.dumps(value))
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415

    client, deadline, poll = storage_client(value), monotonic() + 60, Event()
    while True:
        try:
            client.create_bucket(Bucket=value["bucket"])
            break
        except (BotoCoreError, ClientError):
            if monotonic() >= deadline:
                raise ValueError("Native storage did not become ready; retain its manifest for exact cleanup") from None
            poll.wait(1)
    verify(path)
    write_private(
        environment,
        "PRAHO_NATIVE_S3_ENDPOINT_URL="
        + value["endpoint"]
        + "\nPRAHO_NATIVE_S3_BUCKET="
        + value["bucket"]
        + "\nPRAHO_NATIVE_S3_ACCESS_KEY_ID="
        + value["access_key"]
        + "\nPRAHO_NATIVE_S3_SECRET_ACCESS_KEY="
        + value["secret_key"]
        + "\n",
    )
    print("Native storage verified; environment references are in the private manifest sibling .env file")


def verify(path: Path) -> None:
    value = read_fixture(path)
    owned_container(value)
    client = storage_client(value)
    client.head_bucket(Bucket=value["bucket"])
    key, body = "fixture-proof", b"native backup encrypted storage proof"
    client.put_object(Bucket=value["bucket"], Key=key, Body=body, ServerSideEncryption="AES256")
    result = client.get_object(Bucket=value["bucket"], Key=key)
    if result.get("ServerSideEncryption") != "AES256" or result["Body"].read() != body:
        raise ValueError("Native storage did not preserve the real encrypted backup bytes")
    client.delete_object(Bucket=value["bucket"], Key=key)


def destroy(path: Path) -> None:
    value = read_fixture(path)
    container = owned_container(value)
    if container.get("ExecIDs"):
        raise ValueError("Native storage has an active exec; wait for it to finish before exact cleanup")
    command(["docker", "rm", "--force", value["container_id"]])
    path.with_suffix(path.suffix + ".env").unlink(missing_ok=True)
    path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create", "verify", "destroy"])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--vm-manifest", type=Path)
    args = parser.parse_args()
    if args.action == "create":
        if args.vm_manifest is None:
            parser.error("create requires the exact native --vm-manifest")
        create(args.manifest, run=manifest_run(args.vm_manifest))
    else:
        (verify if args.action == "verify" else destroy)(args.manifest)


if __name__ == "__main__":
    main()
