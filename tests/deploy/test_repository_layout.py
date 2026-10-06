"""Keep production images and Compose mounts in the repository layout."""

from __future__ import annotations

import json
import shlex
from pathlib import Path, PurePosixPath
from typing import cast

import yaml
from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]


def _runtime_instructions(service: str) -> list[tuple[str, str]]:
    source = (ROOT / f"deploy/{service}/Dockerfile").read_text(encoding="utf-8").replace("\\\n", " ")
    instructions: list[tuple[str, str]] = []
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keyword, argument = stripped.split(maxsplit=1)
        if keyword.upper() == "FROM":
            instructions.clear()
        else:
            instructions.append((keyword.upper(), argument))
    return instructions


class DockerRepositoryLayoutTests(SimpleTestCase):
    def _assert_runtime_layout(self, service: str) -> None:
        instructions = _runtime_instructions(service)
        workdir = PurePosixPath("/")
        copies: dict[str, str] = {}
        for keyword, argument in instructions:
            if keyword == "WORKDIR":
                workdir = workdir / argument
            elif keyword == "COPY":
                parts = shlex.split(argument)
                if not parts[0].startswith("--"):
                    copies[parts[0]] = str(workdir / parts[-1])
        self.assertEqual(copies.get(f"services/{service}/"), f"/app/services/{service}")
        self.assertEqual(copies.get("shared/"), "/app/shared")
        self.assertEqual(str(workdir), f"/app/services/{service}")
        entrypoints = [argument for keyword, argument in instructions if keyword == "ENTRYPOINT"]
        self.assertEqual(len(entrypoints), 1)
        self.assertEqual(json.loads(entrypoints[0]), [f"/app/deploy/{service}/entrypoint.sh"])
        self.assertEqual(copies.get(f"deploy/{service}/entrypoint.sh"), f"/app/deploy/{service}/entrypoint.sh")
        environments = " ".join(argument for keyword, argument in instructions if keyword == "ENV")
        self.assertIn(f"PYTHONPATH=/app/services/{service}", environments)
        self.assertIn("/app/.venv/bin:$PATH", environments)

    def test_platform_image_preserves_repository_layout(self) -> None:
        self._assert_runtime_layout("platform")

    def test_portal_image_preserves_repository_layout(self) -> None:
        self._assert_runtime_layout("portal")

    def test_compose_workdirs_and_mounts_match_the_images(self) -> None:
        paths = sorted((ROOT / "deploy").glob("docker-compose*.yml"))
        self.assertEqual(len(paths), 6)
        checked = 0
        for path in paths:
            compose = cast(dict[str, dict[str, dict[str, object]]], yaml.safe_load(path.read_text(encoding="utf-8")))
            for service in ("platform", "portal"):
                if service not in compose["services"]:
                    continue
                checked += 1
                config = compose["services"][service]
                with self.subTest(path=path.name, service=service):
                    self.assertEqual(config.get("working_dir"), f"/app/services/{service}")
                    volumes = config.get("volumes", [])
                    self.assertIsInstance(volumes, list)
                    for volume in cast(list[str], volumes):
                        target = volume.split(":")[1]
                        self.assertNotIn(target, {"/app", "/app/staticfiles", "/app/media", "/app/logs"})
                    if path.name == "docker-compose.dev.yml":
                        self.assertIn(f"../services/{service}:/app/services/{service}:delegated", volumes)
                        self.assertIn("../shared:/app/shared:delegated", volumes)
                        self.assertEqual(
                            config["command"],
                            [
                                "python",
                                f"/app/services/{service}/manage.py",
                                "runserver",
                                f"0.0.0.0:{8700 if service == 'platform' else 8701}",
                            ],
                        )
        self.assertEqual(checked, 10)
