"""The shipped corresponding source must not depend on its Docker builder CPU."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.docker


def test_archived_toolchain_provenance_is_independent_of_builder_cpu() -> None:
    lock = json.loads((ROOT / "deploy/crowdsec/artifacts.lock.json").read_text())
    build = lock["bouncer_build"]
    expected = f"go{build['go_version']}\n".encode()
    output = ROOT / "build/crowdsec-patched"
    assert (output / "toolchain.txt").read_bytes() == expected
    with tarfile.open(ROOT / build["notices"]["file"], "r:gz") as archive:
        provenance = archive.extractfile("./build/toolchain.txt")
        assert provenance is not None
        assert provenance.read() == expected
        for architecture in ("amd64", "arm64"):
            build_info = archive.extractfile(f"./build/build-info-{architecture}.txt")
            assert build_info is not None
            assert f"\tbuild\tGOARCH={architecture}\n".encode() in build_info.read()
