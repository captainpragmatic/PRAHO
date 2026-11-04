"""The application, node helper and deployment lock must pin the same artifacts."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from apps.provisioning import crowdsec_policy

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "deploy/crowdsec"


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def test_application_qualification_pins_the_actual_committed_artifacts() -> None:
    lock_path = ARTIFACTS / "artifacts.lock.json"
    lock = json.loads(lock_path.read_text())
    assert sha256(lock_path) == crowdsec_policy.EXPECTED_ARTIFACT_LOCK_SHA256
    assert sha256(ROOT / "deploy/ansible/roles/crowdsec/files/gateway.py") == crowdsec_policy.EXPECTED_HELPER_SHA256
    assert lock["gateway"]["sha256"] == crowdsec_policy.EXPECTED_HELPER_SHA256
    assert {
        architecture: binary["sha256"] for architecture, binary in lock["bouncer_build"]["binaries"].items()
    } == crowdsec_policy.EXPECTED_BOUNCER_SHA256


def test_build_recipe_and_patches_match_the_locked_inputs() -> None:
    lock = json.loads((ARTIFACTS / "artifacts.lock.json").read_text())
    build = lock["bouncer_build"]
    for field in ("patch", "recipe", "build_script"):
        assert sha256(ARTIFACTS / build[field]["path"]) == build[field]["sha256"]
    assert build["builder_image"] in (ARTIFACTS / build["recipe"]["path"]).read_text()
    assert set(build["binaries"]) == {"amd64", "arm64"}


def test_archived_indexes_link_signed_release_hashes_to_locked_packages() -> None:
    lock = json.loads((ARTIFACTS / "artifacts.lock.json").read_text())
    repository = lock["repository"]
    assert sha256(ARTIFACTS / repository["key_file"]) == repository["key_sha256"]
    release = ARTIFACTS / repository["inrelease_file"]
    assert sha256(release) == repository["inrelease_sha256"]
    signed_sha256_section = (
        release.read_text().split("\nSHA256:\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    )
    for architecture, index in repository["indexes"].items():
        path = ARTIFACTS / index["file"]
        assert sha256(path) == index["sha256"]
        assert path.stat().st_size == index["size"]
        assert f" {index['sha256']} {index['size']} {index['path']}\n" in signed_sha256_section
        records = []
        for paragraph in gzip.decompress(path.read_bytes()).decode().split("\n\n"):
            record = dict(
                line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" ")
            )
            records.append(record)
        for name, package in lock["packages"][architecture].items():
            found = [
                item for item in records if item.get("Package") == name and item.get("Version") == package["version"]
            ]
            assert len(found) == 1
            assert found[0]["Architecture"] == architecture
            assert found[0]["SHA256"] == package["sha256"]
            assert int(found[0]["Size"]) == package["size"]
            assert package["url"] == repository["url"] + found[0]["Filename"]


def test_all_selected_leaves_have_unique_fixed_destinations_and_host_scope() -> None:
    lock = json.loads((ARTIFACTS / "artifacts.lock.json").read_text())
    leaves = lock["hub"]["files"]
    assert len(leaves) == 14
    assert leaves[-1]["path"] == "scenarios/andreasbrett/webmin-bf.yaml"
    destinations = set()
    for leaf in leaves:
        parts = leaf["path"].split("/")
        expected = (
            f"/etc/crowdsec/parsers/{parts[1]}/{parts[3]}"
            if parts[0] == "parsers"
            else f"/etc/crowdsec/scenarios/{parts[2]}"
        )
        assert leaf["installed_path"] == expected
        assert expected not in destinations
        destinations.add(expected)
        assert set(leaf["host_kinds"]) <= {"node", "portal"}
        assert leaf["host_kinds"]
        assert (
            leaf["url"] == f"https://raw.githubusercontent.com/crowdsecurity/hub/{lock['hub']['commit']}/{leaf['path']}"
        )
    assert len([leaf for leaf in leaves if "node" in leaf["host_kinds"]]) == 13
    assert len([leaf for leaf in leaves if "portal" in leaf["host_kinds"]]) == 11
