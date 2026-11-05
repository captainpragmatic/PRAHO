"""A retry may repair bootstrap, but cannot bypass protection of real application data."""

import importlib
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def inspector(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(ROOT / "deploy/scripts"))
    return importlib.import_module("native_install_state")


@pytest.mark.parametrize("service", ["platform", "portal"])
def test_checkout_without_application_data_is_retryable(inspector, tmp_path: Path, service: str) -> None:
    root = tmp_path / "application"
    (root / "src/.git").mkdir(parents=True)
    assert (
        inspector.inspect_installation(
            service, root, tmp_path / "state", tmp_path / "media", "praho", tmp_path / "postgres"
        )
        is False
    )


@pytest.mark.parametrize("database_exists", [False, True])
def test_empty_business_database_does_not_turn_partial_bootstrap_into_a_recovery(
    inspector, tmp_path: Path, database_exists: bool
) -> None:
    postgres = tmp_path / "postgres"
    postgres.mkdir()
    results = [subprocess.CompletedProcess([], 0, "postgres\npraho\n" if database_exists else "postgres\n", "")]
    if database_exists:
        results.append(subprocess.CompletedProcess([], 0, "f\n", ""))
    with patch("native_install_state.subprocess.run", side_effect=results):
        assert (
            inspector.inspect_installation(
                "platform", tmp_path / "root", tmp_path / "state", tmp_path / "media", "praho", postgres
            )
            is False
        )


@pytest.mark.parametrize("kind", ["database", "media", "portal"])
def test_data_without_recovery_prerequisites_fails_closed(inspector, tmp_path: Path, kind: str) -> None:
    postgres, state, media = (tmp_path / name for name in ("postgres", "state", "media"))
    results = []
    if kind == "database":
        postgres.mkdir()
        results = [subprocess.CompletedProcess([], 0, "praho\n", ""), subprocess.CompletedProcess([], 0, "t\n", "")]
    elif kind == "media":
        media.mkdir()
        (media / "customer-upload").touch()
    else:
        state.mkdir()
        (state / "portal.sqlite3").touch()
    with (
        patch("native_install_state.subprocess.run", side_effect=results),
        pytest.raises(ValueError, match="Application data exists"),
    ):
        inspector.inspect_installation(
            "portal" if kind == "portal" else "platform", tmp_path / "root", state, media, "praho", postgres
        )


def test_an_unreachable_existing_database_is_never_treated_as_empty(inspector, tmp_path: Path) -> None:
    postgres = tmp_path / "postgres"
    postgres.mkdir()
    with (
        patch(
            "native_install_state.subprocess.run",
            return_value=subprocess.CompletedProcess([], 2, "", "private diagnostic"),
        ),
        pytest.raises(ValueError, match="could not be inspected") as error,
    ):
        inspector.inspect_installation(
            "platform", tmp_path / "root", tmp_path / "state", tmp_path / "media", "praho", postgres
        )
    assert "private diagnostic" not in str(error.value)


@pytest.mark.parametrize("kind", ["database", "media", "portal"])
def test_installed_data_selects_recovery_instead_of_bootstrap(inspector, tmp_path: Path, kind: str) -> None:
    root, postgres, state, media = (tmp_path / name for name in ("root", "postgres", "state", "media"))
    for path in (root / "src/.git", root / ".venv-linux/bin", root / "scripts", state, media):
        path.mkdir(parents=True)
    (root / ".venv-linux/bin/python").touch()
    results = []
    if kind == "portal":
        (root / ".portal.env").write_text("")
        (state / "portal.sqlite3").touch()
    else:
        (root / "scripts/backup.sh").touch()
        if kind == "database":
            postgres.mkdir()
            (root / ".env").write_text("DB_NAME=praho\n")
            results = [subprocess.CompletedProcess([], 0, "praho\n", ""), subprocess.CompletedProcess([], 0, "t\n", "")]
        else:
            # Media alone is valuable even if no business database was created.
            (root / ".env").write_text("")
            postgres.mkdir()
            results = [subprocess.CompletedProcess([], 0, "postgres\n", "")]
            (media / "customer-file").touch()
    with patch("native_install_state.subprocess.run", side_effect=results):
        assert (
            inspector.inspect_installation(
                "portal" if kind == "portal" else "platform", root, state, media, "praho", postgres
            )
            is True
        )
