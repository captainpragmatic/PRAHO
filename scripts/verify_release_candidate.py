#!/usr/bin/env python3
"""Prove a master commit is the tree its pull request's required checks passed on.

release-candidate.yml runs this before the expensive release checks:

    python3 scripts/verify_release_candidate.py <candidate-sha>

It exits non-zero, saying why, unless all of these hold:
- the candidate came from a pull request merged into master;
- the candidate's tree equals the tree of that PR's final head (an owner bypass can merge a PR whose
  branch was behind master, and the squash then holds code the checks never saw);
- every check master's ruleset requires concluded `success` in that head's latest pull_request run,
  read per workflow, so a same-named job from a dispatched or scheduled run can never stand in for
  it. The one check allowed to be `skipped` is the lab's, and only when its own `changes` job
  succeeded in the same run and that run completed successfully (a cancelled run also skips it).

Needs `gh` (authenticated) and `git` with the PR head fetchable from origin.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
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


def same_tree(repo: Path, first: str, second: str) -> bool:
    def tree(revision: str) -> str:
        return _run(["git", "rev-parse", f"{revision}^{{tree}}"], cwd=repo)

    return tree(first) == tree(second)


def _run(command: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _gh(path: str) -> Any:
    return json.loads(_run(["gh", "api", path]))


def verify(sha: str, repo: str, checkout: Path) -> str:
    pulls = _gh(f"repos/{repo}/commits/{sha}/pulls")
    merged = [pull for pull in pulls if pull.get("merged_at") and pull["base"]["ref"] == "master"]
    if not merged:
        raise VerificationError(f"{sha} did not come from a pull request merged into master")
    number = merged[0]["number"]
    head = _gh(f"repos/{repo}/pulls/{number}")["head"]["sha"]
    _run(["git", "fetch", "--quiet", "origin", f"pull/{number}/head"], cwd=checkout)
    if not same_tree(checkout, sha, head):
        raise VerificationError(
            f"PR #{number}'s final head {head} does not have the candidate's tree: it was merged while behind "
            "master. Land a pull request whose checks ran on the current tree, then release that."
        )
    runs = _gh(f"repos/{repo}/actions/runs?head_sha={head}&event=pull_request&per_page=100")["workflow_runs"]
    for run in runs:
        run["jobs"] = _gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    problems = failed_checks(
        required_contexts(json.loads(RULESET.read_text(encoding="utf-8"))), check_conclusions(runs)
    )
    if problems:
        raise VerificationError(
            f"PR #{number} did not pass every required check on {head}:\n  " + "\n  ".join(problems)
        )
    return f"PR #{number} passed every required check on the candidate's tree ({head})"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <candidate-sha>", file=sys.stderr)
        return 2
    try:
        print(verify(argv[1], os.environ["GITHUB_REPOSITORY"], Path.cwd()))
    except (VerificationError, subprocess.CalledProcessError, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
