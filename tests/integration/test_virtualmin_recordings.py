"""The committed Virtualmin recordings are clean, complete and compared against the node by the drift check.

No lab needed: the contract run (`make test-virtualmin-contract`) writes the recordings and checks drift; these
tests pin what a committed recording must be and prove the drift check reports a change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.virtualmin_lab import drift
from tests.virtualmin_lab.sanitise import find_leaks, sanitise_recording

pytestmark = pytest.mark.integration

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "services/platform/tests/fixtures/virtualmin"
VALIDATORS = Path(__file__).resolve().parents[2] / "services/platform/apps/provisioning/virtualmin_validators.py"


def _committed_fixtures() -> list[Path]:
    return sorted(FIXTURE_ROOT.glob("*/*.json"))


class TestCommittedFixtures:
    def test_there_are_committed_recordings(self) -> None:
        assert len(_committed_fixtures()) >= 36, f"run: make test-virtualmin-contract RECORD=update ({FIXTURE_ROOT})"

    @pytest.mark.parametrize("path", _committed_fixtures(), ids=lambda path: f"{path.parent.name}/{path.name}")
    def test_every_recording_is_already_sanitised(self, path: Path) -> None:
        recording = json.loads(path.read_text())
        assert find_leaks(recording) == []
        assert sanitise_recording(recording) == recording, "re-run the contract suite: the fixture is not a fixed point"
        assert recording["program"] == path.stem
        assert recording["virtualmin_version"] == path.parent.name
        for name, case in recording["cases"].items():
            assert set(case) == {"note", "params", "http_status", "body_format", "body", "classification"}, name


class TestDriftCheck:
    def _copy(self, source: Path, target: Path) -> Path:
        target.mkdir(parents=True)
        for path in source.glob("*.json"):
            (target / path.name).write_text(path.read_text())
        return target

    def _version_dir(self) -> Path:
        return max(path for path in FIXTURE_ROOT.iterdir() if path.is_dir() and path.name[:1].isdigit())

    def test_identical_recordings_report_nothing(self, tmp_path: Path) -> None:
        fresh = self._copy(self._version_dir(), tmp_path / "fresh")
        assert drift.compare(fresh, self._version_dir()) == []

    def test_a_changed_answer_is_reported_with_the_diff(self, tmp_path: Path) -> None:
        fresh = self._copy(self._version_dir(), tmp_path / "fresh")
        path = fresh / "list-domains.json"
        recording = json.loads(path.read_text())
        recording["cases"]["absent_domain"]["body"]["error"] = "Domain does not exist any more"
        path.write_text(json.dumps(recording))

        report = drift.compare(fresh, self._version_dir())

        assert len(report) == 1
        assert report[0].startswith("list-domains.json [absent_domain] differs")
        assert "-    \"error\": \"Virtual server contract-absent.praho.test does not exist\"" in report[0]
        assert "+    \"error\": \"Domain does not exist any more\"" in report[0]

    def test_a_program_or_case_that_appears_or_vanishes_is_reported(self, tmp_path: Path) -> None:
        fresh = self._copy(self._version_dir(), tmp_path / "fresh")
        (fresh / "info.json").unlink()
        recording = json.loads((fresh / "list-plans.json").read_text())
        recording["cases"]["new_case"] = recording["cases"]["success"]
        (fresh / "list-plans.json").write_text(json.dumps(recording))

        report = drift.compare(fresh, self._version_dir())

        assert "info.json: committed, but the fresh run did not record it" in report
        assert "list-plans.json [new_case]: recorded by the fresh run, not committed" in report

    def test_the_command_exits_non_zero_on_drift_and_zero_without(self, tmp_path: Path) -> None:
        version = self._version_dir()
        fresh_root = tmp_path / "fresh"
        fresh = self._copy(version, fresh_root / version.name)
        arguments = ["--fresh", str(fresh_root), "--committed", str(FIXTURE_ROOT)]
        assert drift.main(arguments) == 0
        (fresh / "info.json").unlink()
        assert drift.main(arguments) == 1
        assert drift.main(["--fresh", str(tmp_path / "nothing"), "--committed", str(FIXTURE_ROOT)]) == 2
