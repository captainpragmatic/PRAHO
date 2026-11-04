#!/usr/bin/env python3
"""Prove the merge queue tested a master commit with every required check.

release-candidate.yml runs this before the expensive release checks:

    python3 scripts/verify_release_candidate.py <candidate-sha>

The merge queue builds each commit it lands on master and runs the required checks on that exact
commit (event `merge_group`) before master moves to it. So the candidate is vouched for by its own runs,
not by its pull request's: a pull request's runs saw its branch, which may have been behind master.

It exits non-zero, saying why, unless every check master's ruleset requires concluded `success` in the
candidate's latest merge_group run, read per workflow, so a same-named job from a dispatched or
scheduled run can never stand in for it. The one check allowed to be `skipped` is the lab's, and only
when its own `changes` job succeeded in the same run and that run completed successfully (a cancelled
run also skips it). A commit with no merge_group run was merged around the queue (an owner bypass), and
is refused.

It also requires explicit native-inclusive full Virtualmin acceptance on this exact master SHA,
including the actual successful native capability step. Routine container, drift or historical
pre-native full success cannot qualify a candidate. A configured admission flag is never proof.

Needs `gh` (authenticated).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

# GitHub's REST payloads, as parsed JSON.
JSONObject = dict[str, Any]

RULESET = Path(__file__).resolve().parents[1] / ".github" / "rulesets" / "master.json"
SELECTIVE = {"pull-request": "changes"}  # a check allowed to skip -> the job whose success must explain it
RUN_CONCLUSION = " run"  # key for each workflow run's own conclusion (job names never start with a space)


class VerificationError(Exception):
    """The candidate cannot be vouched for."""


def required_contexts(ruleset: JSONObject) -> list[str]:
    rules = [rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks"]
    contexts = [check["context"] for rule in rules for check in rule["parameters"]["required_status_checks"]]
    if not contexts:
        raise VerificationError("master's ruleset lists no required checks: refusing to vouch on nothing")
    return contexts


def check_conclusions(runs: Iterable[JSONObject]) -> dict[str, list[tuple[str, str]]]:
    """Job name -> [(workflow path, conclusion)] from the newest pull_request run of each workflow."""
    newest: dict[str, JSONObject] = {}
    for run in runs:
        path = str(run["path"])
        if path not in newest or int(run["id"]) > int(newest[path]["id"]):
            newest[path] = run
    jobs: dict[str, list[tuple[str, str]]] = {}
    for path, run in newest.items():
        # The run's own conclusion, under a name no job can have: a cancelled run skips jobs too.
        jobs.setdefault(RUN_CONCLUSION, []).append((path, str(run.get("conclusion"))))
        for job in run["jobs"]:
            jobs.setdefault(str(job["name"]), []).append((path, str(job.get("conclusion"))))
    return jobs


def failed_checks(contexts: Iterable[str], jobs: Mapping[str, list[tuple[str, str]]]) -> list[str]:
    """Every required context that did not pass, with the reason."""
    problems: list[str] = []
    for context in contexts:
        found = jobs.get(context, [])
        if len(found) != 1:
            problems.append(f"{context}: {'never reported' if not found else 'reported by several workflows'}")
            continue
        path, conclusion = found[0]
        if conclusion == "success":
            continue
        decider = SELECTIVE.get(context)
        if (
            conclusion == "skipped"
            and decider
            and (path, "success") in jobs.get(decider, [])
            and (path, "success") in jobs.get(RUN_CONCLUSION, [])
        ):
            continue
        problems.append(f"{context}: {conclusion} ({path})")
    return problems


def _run(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


def _gh(path: str) -> Any:
    return json.loads(_run(["gh", "api", path]))


def verify(sha: str, repo: str, gh: Callable[[str], Any] = _gh) -> str:
    runs = gh(f"repos/{repo}/actions/runs?head_sha={sha}&event=merge_group&per_page=100")["workflow_runs"]
    if not runs:
        raise VerificationError(
            f"The merge queue never tested {sha}: it was merged around the queue. "
            "Land a pull request through the queue, then release that."
        )
    for run in runs:
        run["jobs"] = gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    problems = failed_checks(
        required_contexts(json.loads(RULESET.read_text(encoding="utf-8"))), check_conclusions(runs)
    )
    if problems:
        raise VerificationError(
            f"The merge queue did not pass every required check on {sha}:\n  " + "\n  ".join(problems)
        )
    lab = latest_full_lab(repo, gh, sha=sha)
    return f"The merge queue passed every required check on the candidate itself ({sha}), and {lab}"


# Container schedules and native acceptance have different scopes and job identities.
NIGHTLY_LAB_WORKFLOW = "virtualmin-lab.yml"
NIGHTLY_FULL_JOB = "native-full"
NATIVE_CAPABILITY_STEP = "Verify fresh Ubuntu native hosting capability"
CONTAINER_JOB = "nightly-containers"


NIGHTLY_ACTIVITY_JOB = "check-activity"
NIGHTLY_DRIFT_JOB = "nightly-drift"
_MAX_PAGES = 20  # 600 runs: months of nightly and drift runs


def _master_lab_runs(repo: str, gh: Callable[[str], Any]) -> Iterator[dict[str, Any]]:
    """Completed lab runs on master, newest first, page by page until the history ends."""
    for page in range(1, _MAX_PAGES + 1):
        listed = gh(
            f"repos/{repo}/actions/workflows/{NIGHTLY_LAB_WORKFLOW}/runs"
            f"?branch=master&status=completed&per_page=30&page={page}"
        )["workflow_runs"]
        if not listed:
            return
        yield from sorted(listed, key=lambda run: int(run["id"]), reverse=True)


def _routine_lab_run(jobs: dict[str, JSONObject], run: JSONObject) -> bool:
    """Routine/drift/quiet evidence may be passed over, never accepted as native proof."""
    drift = any(
        name.startswith(NIGHTLY_DRIFT_JOB) and job.get("conclusion") not in (None, "skipped")
        for name, job in jobs.items()
    )
    containers = jobs.get(CONTAINER_JOB, {}).get("conclusion") not in (None, "skipped")
    quiet = (
        CONTAINER_JOB in jobs
        and jobs[CONTAINER_JOB].get("conclusion") == "skipped"
        and jobs.get(NIGHTLY_ACTIVITY_JOB, {}).get("conclusion") == "success"
        and run.get("conclusion") == "success"
    )
    return drift or containers or quiet


def latest_full_lab(repo: str, gh: Callable[[str], Any] = _gh, *, sha: str) -> str:
    """Explicit native-inclusive full acceptance on this exact master candidate.

    Routine container, drift and genuine quiet runs cannot replace a native job or
    capability step. Historical pre-native full jobs never supply physical proof.
    A failed/canceled native attempt cannot fall back to an older success.
    """
    for run in _master_lab_runs(repo, gh):
        if run.get("head_branch") != "master":
            continue
        jobs = {
            job["name"]: job
            for job in gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
        }
        full = jobs.get(NIGHTLY_FULL_JOB, {})
        if full.get("conclusion") in (None, "skipped"):
            if _routine_lab_run(jobs, run):
                continue
            raise VerificationError(
                f"The full Virtualmin lab on master (run {run['id']}, {run.get('conclusion')}) has no completed native job. "
                f"Configure the approved runner/authority, then dispatch {NIGHTLY_LAB_WORKFLOW} with suite full."
            )
        if run.get("head_sha") != sha:
            continue
        if full.get("conclusion") != "success" or run.get("conclusion") != "success":
            raise VerificationError(
                f"The latest full Virtualmin lab on master for {sha} (run {run['id']}) did not pass: "
                f"{full.get('conclusion')}/{run.get('conclusion')}."
            )
        capability = [step for step in full.get("steps", []) if step.get("name") == NATIVE_CAPABILITY_STEP]
        if (
            run.get("event") != "workflow_dispatch"
            or len(capability) != 1
            or capability[0].get("conclusion") != "success"
        ):
            raise VerificationError(
                f"The full Virtualmin lab on master (run {run['id']}) lacks explicit successful native capability evidence."
            )
        return f"the native-inclusive full Virtualmin lab on this master candidate passed (run {run['id']})"
    raise VerificationError(
        f"No native-inclusive full Virtualmin lab on master qualifies {sha}. "
        f"Configure the approved runner/authority, then dispatch {NIGHTLY_LAB_WORKFLOW} with suite full on that SHA."
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <candidate-sha>", file=sys.stderr)
        return 2
    try:
        print(verify(argv[1], os.environ["GITHUB_REPOSITORY"]))
    except (VerificationError, subprocess.CalledProcessError, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
