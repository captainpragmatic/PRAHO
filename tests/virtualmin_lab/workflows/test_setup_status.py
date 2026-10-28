"""Status resource normalization and off-server backup evidence against real lab services."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import paramiko
import pytest
from botocore.exceptions import ClientError
from django.test import override_settings

from apps.common.platform_backup import BackupArtifact, PlatformBackupPublisher
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.provisioning.management.commands._virtualmin_lab import lab_transport
from apps.provisioning.virtualmin_backup_service import backup_storage_client
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.virtualmin_lab.contract.harness import assert_accepted
from tests.virtualmin_lab.workflows.harness import Bench, DomainData


def test_live_info_retains_numeric_cpu_memory_and_disk(bench: Bench) -> None:
    result = bench.lab("vm-a").gateway.get_server_info()
    assert result.is_ok(), result
    resources = VirtualminGateway.resource_snapshot(result.unwrap())
    assert resources.cpu_percent is not None
    assert resources.memory_percent is not None
    assert resources.disk_percent is not None
    assert all(0 <= metric <= 100 for metric in (resources.cpu_percent, resources.memory_percent, resources.disk_percent))
    assert resources.details()["measurement_time_known"] is False


def test_platform_pair_is_verified_through_real_minio_multipart(bench: Bench) -> None:
    client = backup_storage_client()
    bucket = str(SettingsService.get_setting("backup.s3_bucket_name"))
    source, run = uuid4(), uuid4()
    publisher = PlatformBackupPublisher(client, bucket, source)
    bodies = {"database": b"d" * (9 * 1024 * 1024), "media": b"documents" * 1024}
    artifacts = [BackupArtifact(role, len(body), hashlib.sha256(body).hexdigest()) for role, body in bodies.items()]
    prefix = f"platform-backups/{source}/{run}"
    try:
        for artifact in artifacts:
            publisher.upload(run, artifact, io.BytesIO(bodies[artifact.role]))
        key = publisher.publish(run, artifacts)
        response = client.get_object(Bucket=bucket, Key=key)
        try:
            manifest = json.loads(response["Body"].read())
        finally:
            response["Body"].close()
        assert response["ServerSideEncryption"] == "AES256"
        assert manifest["run_id"] == str(run)
        assert {item["sha256"] for item in manifest["artifacts"]} == {item.sha256 for item in artifacts}
        with pytest.raises(ClientError) as retry:
            publisher.upload(run, artifacts[0], io.BytesIO(bodies["database"]))
        assert retry.value.response["Error"]["Code"] == "PreconditionFailed"
        with pytest.raises(ClientError) as marker:
            publisher.publish(run, artifacts)
        assert marker.value.response["Error"]["Code"] == "PreconditionFailed"
        race_key = f"{prefix}/conditional-race"
        multipart = client.create_multipart_upload(Bucket=bucket, Key=race_key, ServerSideEncryption="AES256")
        try:
            part = client.upload_part(Bucket=bucket, Key=race_key, UploadId=multipart["UploadId"], PartNumber=1, Body=b"loser")
            client.put_object(Bucket=bucket, Key=race_key, Body=b"winner", ServerSideEncryption="AES256")
            with pytest.raises(ClientError) as conflict:
                client.complete_multipart_upload(Bucket=bucket, Key=race_key, UploadId=multipart["UploadId"],
                                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]}, IfNoneMatch="*")
            assert conflict.value.response["Error"]["Code"] == "PreconditionFailed"
            winner = client.get_object(Bucket=bucket, Key=race_key)["Body"]
            try:
                assert winner.read() == b"winner"
            finally:
                winner.close()
        finally:
            client.abort_multipart_upload(Bucket=bucket, Key=race_key, UploadId=multipart["UploadId"])
    finally:
        for name in ("database", "media", "manifest.json", "conditional-race"):
            client.delete_object(Bucket=bucket, Key=f"{prefix}/{name}")


def test_imported_server_backup_restore_without_deployment_row(bench: Bench) -> None:
    with bench.hosted("wfimportedbackup.example.com") as account:
        original = account.server
        lab = bench.lab_of(account)
        data = DomainData(lab, account)
        data.seed("imported-backup-proof")
        before = data.snapshot()
        private_key = get_ssh_key_manager().get_private_key_file(original.node_deployment, reason="Imported backup lab proof").unwrap()
        imported = VirtualminServer(name="Imported lab server", hostname="localhost", api_port=bench.node("vm-a").api_port,
                                   api_username=original.api_username, ssh_port=bench.node("vm-a").ssh_port,
                                   ssl_verify=False, ssl_cert_fingerprint=original.ssl_cert_fingerprint)
        imported.set_api_password(original.get_api_password())
        imported.save()
        assert getattr(imported, "node_deployment", None) is None
        try:
            account.server = imported
            account.save(update_fields=["server", "updated_at"])
            with TemporaryDirectory(prefix="praho-imported-lab-") as directory:
                trust = paramiko.HostKeys(bench.state.known_hosts)
                keys = trust.lookup(f"[127.0.0.1]:{imported.ssh_port}")
                assert keys is not None
                for algorithm, key in keys.items():
                    trust.add(f"[localhost]:{imported.ssh_port}", algorithm, key)
                known_hosts = Path(directory) / "known_hosts"
                trust.save(str(known_hosts))
                local_node = replace(bench.node("vm-a"), server_hostname="localhost", deployment_hostname="imported-local")
                local_state = replace(bench.state, nodes=(*bench.state.nodes, local_node), known_hosts=str(known_hosts))
                with override_settings(SETTINGS_MODULE="config.settings.lab"), lab_transport(local_state), override_settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(private_key)):
                    backup = bench.backup(account)
                    assert backup.status == "completed", backup.status_message
                    assert_accepted(lab.quiet("delete-domain", {"domain": account.domain}))
                    restored = bench.restore(account, backup.result["backup_id"])
                    assert restored.status == "completed", restored.status_message
                    assert data.snapshot() == before
        finally:
            account.server = original
            account.save(update_fields=["server", "updated_at"])
            imported.delete()
            Path(private_key).unlink(missing_ok=True)
