"""Controller verification must authenticate repository metadata, not its labels."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def verifier() -> ModuleType:
    path = ROOT / "deploy/crowdsec/verify_artifacts.py"
    spec = importlib.util.spec_from_file_location("crowdsec_artifact_verifier", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_actual_archived_repository_signature_and_all_locked_rows_verify(verifier: ModuleType) -> None:
    result = verifier.verify(ROOT / "deploy/crowdsec/artifacts.lock.json")
    assert result == {"verified": True, "package_count": 4, "hub_leaf_count": 14}


def test_actual_key_fingerprint_must_match_the_anchor_not_just_the_lock_label(
    verifier: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_run = verifier._run

    def different_key(argv: list[str]) -> str:
        if "--show-keys" in argv:
            return "pub:-:4096:1:1111111111111111::::::::\nfpr:::::::::" + "A" * 40 + ":\n"
        return real_run(argv)

    # GPG is the external boundary; the verifier's actual primary-key parsing stays real.
    monkeypatch.setattr(verifier, "_run", different_key)
    with pytest.raises(verifier.ArtifactVerificationError, match="verification"):
        verifier.verify(ROOT / "deploy/crowdsec/artifacts.lock.json")


@pytest.mark.parametrize("changed", ["primary", "key_bytes", "index_bytes", "package_row", "escaped_path", "signature"])
def test_tampering_is_refused_before_host_mutation(verifier: ModuleType, tmp_path: Path, changed: str) -> None:
    directory = tmp_path / "artifacts"
    shutil.copytree(ROOT / "deploy/crowdsec", directory)
    path = directory / "artifacts.lock.json"
    lock = json.loads(path.read_text())
    expected_error = "verification"
    if changed == "primary":
        lock["repository"]["primary_fingerprint"] = "A" * 40
    elif changed == "key_bytes":
        (directory / lock["repository"]["key_file"]).write_text("not an OpenPGP key")
    elif changed == "index_bytes":
        (directory / lock["repository"]["indexes"]["arm64"]["file"]).write_bytes(b"invalid index")
    elif changed == "package_row":
        lock["packages"]["arm64"]["crowdsec"]["sha256"] = "0" * 64
    elif changed == "escaped_path":
        lock["repository"]["inrelease_file"] = "../outside"
        (tmp_path / "outside").write_text("untrusted")
    else:
        release = directory / lock["repository"]["inrelease_file"]
        raw = release.read_bytes().replace(b"Label: crowdsec", b"Label: alteredx")
        release.write_bytes(raw)
        lock["repository"]["inrelease_sha256"] = hashlib.sha256(raw).hexdigest()
        expected_error = "signature"
    path.write_text(json.dumps(lock))
    with pytest.raises(verifier.ArtifactVerificationError, match=expected_error):
        verifier.verify(path)
