"""Execute real fixture construction against a fake Docker process boundary only."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import test_component_path_fence_docker as component
import test_crowdsec_bouncer_docker as bouncer
import test_crowdsec_gateway_docker as gateway
import test_network_qualification_docker as network
import test_ssh_hardening_docker as ssh
from fixture_images import fixture_image


class StopBeforeContainerRunError(Exception):
    """The command boundary refuses all actual container/inspection/network work."""


@dataclass
class DockerBoundary:
    images: dict[str, str]
    owner: str = ""
    build_tags: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)

    def run(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[0] == ssh.DOCKER
        args = command[1:]
        self.commands.append(args)
        if args[0] == "build":
            image = args[args.index("-t") + 1]
            source = kwargs.get("input")
            if isinstance(source, str) and source.startswith("FROM "):
                base = source.splitlines()[0].removeprefix("FROM ")
                assert self.images[base] == self.owner, "Derived image used another run's base"
            self.images[image] = self.owner
            self.build_tags.append(image)
            return subprocess.CompletedProcess(command, 0, "", "")
        assert args[0] == "run" or args[:2] == ["image", "inspect"], args
        referenced = [name for name in self.images if name in args]
        assert len(referenced) == 1 and self.images[referenced[0]] == self.owner, "Read/run used a foreign image"
        raise StopBeforeContainerRunError


def _construct_fixture(kind: str, version: str, tmp_path: Path) -> str | None:
    if kind == "component":
        result = component.build_component_image(version)
        assert isinstance(result, str)
        return result
    if kind == "bouncer":
        result = bouncer.bouncer_image.__wrapped__()
        assert isinstance(result, str)
        return result
    if kind == "gateway":
        factory = SimpleNamespace(mktemp=lambda name: tmp_path / name)
        iterator = gateway.native_gateway.__wrapped__(factory)
    else:
        fixture = ssh.ssh_target if kind == "ssh" else network.network_target
        iterator = fixture.__wrapped__(SimpleNamespace(param=version))
    with pytest.raises(StopBeforeContainerRunError):
        next(iterator)
    iterator.close()
    return None


@pytest.mark.parametrize(
    ("kind", "version", "shared"),
    [
        ("ssh", "24.04", ("praho-ssh-test:24.04",)),
        ("ssh", "26.04", ("praho-ssh-test:26.04",)),
        ("network", "24.04", ("praho-ssh-test:24.04", "praho-network-proof:24.04")),
        ("network", "26.04", ("praho-ssh-test:26.04", "praho-network-proof:26.04")),
        ("component", "24.04", ("praho-component-php:24.04",)),
        ("component", "26.04", ("praho-component-php:26.04",)),
        ("bouncer", "26.04", ("praho-ssh-test:26.04", "praho-crowdsec-bouncer-test:26.04")),
        ("gateway", "26.04", ("praho-ssh-test:26.04",)),
    ],
)
def test_fixture_builds_preserve_shared_images_and_other_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str, version: str, shared: tuple[str, ...]
) -> None:
    boundary = DockerBoundary(dict.fromkeys(shared, "pre-existing-shared-image"))
    monkeypatch.setattr(ssh.subprocess, "run", boundary.run)
    tags_by_run = []
    for namespace in ("first-run", "second-run"):
        monkeypatch.setenv("PRAHO_TEST_IMAGE_NAMESPACE", namespace)
        boundary.owner = namespace
        before = len(boundary.build_tags)
        returned = _construct_fixture(kind, version, tmp_path)
        tags = boundary.build_tags[before:]
        assert len(tags) == len(shared), "Fixture build discovery lost a target"
        if returned is not None:
            assert returned == tags[-1], "Fixture returned a different image than it built"
        tags_by_run.append(set(tags))
    assert {name: boundary.images[name] for name in shared} == dict.fromkeys(shared, "pre-existing-shared-image")
    assert tags_by_run[0].isdisjoint(tags_by_run[1]), "Two independent runs reused a mutable tag"
    assert all(boundary.images[tag] == "first-run" for tag in tags_by_run[0])
    assert all(boundary.images[tag] == "second-run" for tag in tags_by_run[1])


@pytest.mark.parametrize("namespace", ["a", "hosting-4bbf8edf-20261104", "a" * 48])
def test_explicit_namespace_is_valid_stable_and_keeps_the_original_tag(
    monkeypatch: pytest.MonkeyPatch, namespace: str
) -> None:
    monkeypatch.setenv("PRAHO_TEST_IMAGE_NAMESPACE", namespace)
    expected = f"praho-test-{namespace}/praho-ssh-test:26.04"
    assert fixture_image("praho-ssh-test:26.04") == expected
    assert fixture_image("praho-ssh-test:26.04") == expected
    assert fixture_image("praho-component-php:24.04") != expected


@pytest.mark.parametrize(
    "namespace",
    [
        "",
        "-run",
        "run-",
        "run--other",
        "Run",
        "run/other",
        "localhost:5000",
        "../run",
        "run_other",
        "run.other",
        " run",
        "run\n",
        "a" * 49,
    ],
)
def test_invalid_namespace_is_refused_without_echoing_it(monkeypatch: pytest.MonkeyPatch, namespace: str) -> None:
    monkeypatch.setenv("PRAHO_TEST_IMAGE_NAMESPACE", namespace)
    with pytest.raises(ValueError) as caught:
        fixture_image("praho-ssh-test:26.04")
    assert str(caught.value) == "A valid private test image namespace is required"


@pytest.mark.parametrize(
    "reference",
    [
        None,
        1,
        "",
        "ubuntu:26.04",
        "docker.io/praho-ssh-test:26.04",
        "praho-ssh-test",
        "praho-ssh-test@sha256:" + "a" * 64,
        "praho-ssh-test:tag/other",
        "praho-ssh-test:tag;id",
        "praho-ssh-test:tag\n",
        "/praho-ssh-test:tag",
        "praho-ssh-test:t extra",
        "praho-" + "a" * 95 + ":tag",
        "praho-ssh-test:" + "a" * 129,
    ],
)
def test_invalid_reference_is_refused_without_echoing_it(monkeypatch: pytest.MonkeyPatch, reference: object) -> None:
    monkeypatch.setenv("PRAHO_TEST_IMAGE_NAMESPACE", "reference-test")
    with pytest.raises(ValueError) as caught:
        fixture_image(cast("str", reference))
    assert str(caught.value) == "A simple test-owned image name and tag are required"


def test_reference_length_boundaries_are_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRAHO_TEST_IMAGE_NAMESPACE", "length-test")
    reference = "praho-" + "a" * 94 + ":" + "b" * 128
    assert fixture_image(reference) == f"praho-test-length-test/{reference}"


def test_default_namespace_is_stable_in_one_process_and_changes_in_another() -> None:
    program = (
        "from fixture_images import fixture_image; "
        "first=fixture_image('praho-ssh-test:26.04'); "
        "assert first==fixture_image('praho-ssh-test:26.04'); print(first)"
    )
    environment = {"PYTHONPATH": str(Path(__file__).parent)}
    outputs = [
        subprocess.check_output(  # noqa: S603 -- Current Python and fixed pure helper program, no Docker or ambient authority.
            [sys.executable, "-c", program], env=environment, text=True, timeout=10
        ).strip()
        for _ in range(2)
    ]
    assert outputs[0] != outputs[1]
    assert all(value.startswith("praho-test-") and value.endswith("/praho-ssh-test:26.04") for value in outputs)


def test_inherited_cache_does_not_reuse_a_parent_process_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRAHO_TEST_IMAGE_NAMESPACE", raising=False)
    monkeypatch.setattr(os, "getpid", lambda: 1001)
    parent = fixture_image("praho-ssh-test:26.04")
    assert fixture_image("praho-ssh-test:26.04") == parent
    monkeypatch.setattr(os, "getpid", lambda: 1002)
    child = fixture_image("praho-ssh-test:26.04")
    assert child != parent
    assert fixture_image("praho-ssh-test:26.04") == child


def test_all_eight_mutable_call_sites_include_the_last_debug_commit() -> None:
    found: dict[str, int] = {}
    debug_seen = False
    for path in Path(__file__).parent.glob("*docker.py"):
        tree = ast.parse(path.read_text())
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "fixture_image"
        ]
        if calls:
            found[path.name] = len(calls)
        if path.name == "test_crowdsec_role_docker.py":
            debug_seen = any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "docker"
                and len(node.args) == 3
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "commit"
                and isinstance(node.args[2], ast.Call)
                and isinstance(node.args[2].func, ast.Name)
                and node.args[2].func.id == "fixture_image"
                and isinstance(node.args[2].args[0], ast.Constant)
                and node.args[2].args[0].value == "praho-crowdsec-role-debug:failed-install"
                for node in ast.walk(tree)
            )
    assert found == {
        "test_ssh_hardening_docker.py": 1,
        "test_network_qualification_docker.py": 2,
        "test_component_path_fence_docker.py": 1,
        "test_crowdsec_bouncer_docker.py": 2,
        "test_crowdsec_gateway_docker.py": 1,
        "test_crowdsec_role_docker.py": 1,
    }
    assert sum(found.values()) == 8
    assert debug_seen, "The discovery helper lost the final optional debug-commit site"
