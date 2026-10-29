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

Needs `gh` (authenticated).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
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
    return f"The merge queue passed every required check on the candidate itself ({sha})"


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
