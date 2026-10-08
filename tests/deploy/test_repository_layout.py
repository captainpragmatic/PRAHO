"""Keep the repository image layout compatible with pre-layout rollback images."""

from __future__ import annotations

import json
import re
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


def _dev_stage(service: str) -> str:
    """The Dockerfile's dev target, from its FROM line to the next stage."""
    stages = re.split(r"^FROM ", (ROOT / "deploy" / service / "Dockerfile").read_text(encoding="utf-8"), flags=re.M)
    return next(stage for stage in stages if stage.split("\n", 1)[0].rstrip().endswith(" AS dev"))


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

    def _assert_legacy_runtime_paths(self, service: str, directories: tuple[str, ...]) -> None:
        instructions = _runtime_instructions(service)
        # Only commands executed before dropping privileges can prepare writable paths.
        user_index = instructions.index(("USER", "django"))
        commands = [
            shlex.split(command.strip())
            for keyword, argument in instructions[:user_index]
            if keyword == "RUN"
            for command in argument.split("&&")
        ]
        ownership = commands.index(["chown", "-R", "django:django", "/app"])
        for directory in directories:
            legacy = f"/app/{directory}"
            relative = f"/app/services/{service}/{directory}"
            move = ["mv", relative, legacy]
            mkdir = ["mkdir", "-p", relative]
            link = ["ln", "-s", legacy, relative]
            with self.subTest(service=service, directory=directory):
                self.assertIn(move, commands)
                self.assertIn(mkdir, commands)
                self.assertIn(link, commands)
                self.assertLess(commands.index(mkdir), commands.index(move))
                self.assertLess(commands.index(move), commands.index(link))
                self.assertLess(commands.index(link), ownership)

    def test_platform_image_uses_legacy_runtime_paths(self) -> None:
        self._assert_legacy_runtime_paths("platform", ("staticfiles", "media", "logs"))

    def test_portal_image_uses_legacy_runtime_paths(self) -> None:
        self._assert_legacy_runtime_paths("portal", ("staticfiles", "logs"))

    def test_portal_image_keeps_the_legacy_default_session_database(self) -> None:
        environments = [
            token
            for keyword, argument in _runtime_instructions("portal")
            if keyword == "ENV"
            for token in shlex.split(argument)
        ]
        self.assertIn("SESSION_DB_PATH=/app/portal.sqlite3", environments)

    def test_portal_session_database_is_inside_a_persistent_compose_mount(self) -> None:
        image_environment = dict(
            token.split("=", 1)
            for keyword, argument in _runtime_instructions("portal")
            if keyword == "ENV"
            for token in shlex.split(argument)
        )
        expected_portal_files = {
            "docker-compose.container-service.yml",
            "docker-compose.dev.yml",
            "docker-compose.portal-only.yml",
            "docker-compose.single-server.yml",
        }
        checked: set[str] = set()
        for path in sorted((ROOT / "deploy").glob("docker-compose*.yml")):
            compose = cast(dict[str, dict[str, dict[str, object]]], yaml.safe_load(path.read_text(encoding="utf-8")))
            if "portal" not in compose["services"]:
                continue
            checked.add(path.name)
            config = compose["services"]["portal"]
            with self.subTest(path=path.name):
                raw_environment = config.get("environment", [])
                self.assertIsInstance(raw_environment, list)
                environment = dict(entry.split("=", 1) for entry in cast(list[str], raw_environment) if "=" in entry)
                session_path = PurePosixPath(environment.get("SESSION_DB_PATH", image_environment["SESSION_DB_PATH"]))
                self.assertTrue(session_path.is_absolute())
                raw_mounts = config.get("volumes", [])
                self.assertIsInstance(raw_mounts, list)
                persistent_destinations: list[PurePosixPath] = []
                for mount in cast(list[str], raw_mounts):
                    parts = mount.split(":")
                    if len(parts) < 2:
                        continue  # Anonymous volumes are not stable across container replacement.
                    source, destination = parts[:2]
                    if source in compose.get("volumes", {}) or source.startswith((".", "/")):
                        persistent_destinations.append(PurePosixPath(destination))
                self.assertTrue(
                    any(
                        session_path != destination and session_path.is_relative_to(destination)
                        for destination in persistent_destinations
                    ),
                    f"{path.name}: {session_path} is outside persistent mounts {persistent_destinations}",
                )
        self.assertEqual(checked, expected_portal_files)

    def test_compose_workdirs_and_mounts_match_the_images(self) -> None:
        expected_volumes: dict[str, dict[str, list[str]]] = {
            "docker-compose.container-service.yml": {
                "platform": [],
                "portal": ["portal_sessions:/app/data"],
            },
            "docker-compose.platform-only.yml": {
                "platform": ["static_files:/app/staticfiles", "media_files:/app/media", "logs:/app/logs"],
            },
            "docker-compose.portal-only.yml": {
                "portal": ["portal_static:/app/staticfiles", "portal_logs:/app/logs", "portal_sessions:/app/data"],
            },
            "docker-compose.single-server.yml": {
                "platform": ["static_files:/app/staticfiles", "media_files:/app/media", "logs:/app/logs"],
                "portal": ["portal_static:/app/staticfiles", "portal_logs:/app/logs", "portal_sessions:/app/data"],
            },
        }
        paths = sorted((ROOT / "deploy").glob("docker-compose*.yml"))
        self.assertEqual({path.name for path in paths}, {*expected_volumes, "docker-compose.dev.yml"})
        checked = 0
        for path in paths:
            compose = cast(dict[str, dict[str, dict[str, object]]], yaml.safe_load(path.read_text(encoding="utf-8")))
            services = compose["services"]
            if path.name != "docker-compose.dev.yml":
                self.assertEqual(set(services) & {"platform", "portal"}, set(expected_volumes[path.name]))
            for service in ("platform", "portal"):
                if service not in services:
                    continue
                checked += 1
                config = services[service]
                with self.subTest(path=path.name, service=service):
                    volumes = config.get("volumes", [])
                    self.assertIsInstance(volumes, list)
                    if path.name == "docker-compose.dev.yml":
                        # The dev image sets the working directory; the mounts must land where it points
                        build = cast(dict[str, str], config["build"])
                        self.assertEqual(build.get("target"), "dev")
                        self.assertIn(f"WORKDIR /app/services/{service}", _dev_stage(service))
                        self.assertNotIn("working_dir", config)
                        self.assertIn(f"../services/{service}:/app/services/{service}:delegated", volumes)
                        self.assertIn("../shared:/app/shared:ro", volumes)
                        port = 8700 if service == "platform" else 8701
                        self.assertIn(f"python manage.py runserver 0.0.0.0:{port}", str(config["command"]))
                    else:
                        self.assertNotIn("working_dir", config)
                        self.assertEqual(volumes, expected_volumes[path.name][service])
                        self.assertNotIn("entrypoint", config)
                        self.assertNotIn("command", config)
        self.assertEqual(checked, 8)
