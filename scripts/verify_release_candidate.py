#!/usr/bin/env python3
"""Prove the merge queue tested a master commit with every required check.

release-candidate.yml runs this before the release checks:

    python3 scripts/verify_release_candidate.py <candidate-sha>     # queue evidence + per-scope decisions
    python3 scripts/verify_release_candidate.py --pick              # newest master commit fully proven

The merge queue builds each commit it lands on master and runs the required checks on that exact
commit (event `merge_group`) before master moves to it. So the candidate is vouched for by its own runs,
not by its pull request's: a pull request's runs saw its branch, which may have been behind master.

It exits non-zero, saying why, unless every check master's ruleset requires concluded `success` in the
candidate's latest merge_group run, read per workflow, so a same-named job from a dispatched or
scheduled run can never stand in for it. The one check allowed to be `skipped` is the lab's, and only
when its own `changes` job succeeded in the same run and that run completed successfully (a cancelled
run also skips it). A commit with no merge_group run was merged around the queue (an owner bypass), and
is refused.

Then, per release scope (``RELEASE_SCOPES``: the whole Platform suite on PostgreSQL, CrowdSec, native
deploy and the Virtualmin lab), it answers ``reuse <run id>`` when a nightly run on master proved that
scope on this exact commit, or ``run`` otherwise, and the release candidate runs those scopes on the
candidate. Evidence from any other commit never counts: an older pass says nothing about a newer change.

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


# A release scope -> (workflow, accepted job names, the step that proves it, or None for the whole job).
# The nightly matrix names its job after the branch it tested; only master's counts.
RELEASE_SCOPES: dict[str, tuple[str, tuple[str, ...], str | None]] = {
    "postgres": ("nightly.yml", ("nightly (master)",), "Whole platform suite on PostgreSQL"),
    # make test-integration collects tests/deploy, CrowdSec's Docker qualification among them.
    "crowdsec": ("nightly.yml", ("nightly (master)",), "Integration tests"),
    "native": ("nightly.yml", ("nightly-native-deploy",), None),
    # "nightly-full" is the container lab's name before node deploy moved to native acceptance.
    "lab": ("virtualmin-lab.yml", ("nightly-containers", "nightly-full"), None),
}
_EVIDENCE_RUNS = 20  # runs of one workflow on one commit: dispatches and reruns


def _ran(job: JSONObject, step_name: str | None) -> bool:
    if step_name is None:
        return job.get("conclusion") not in (None, "skipped")
    steps = [step for step in job.get("steps", []) if step.get("name") == step_name]
    return any(step.get("conclusion") not in (None, "skipped") for step in steps)


def _proof(job: JSONObject, step_name: str | None) -> bool:
    """A whole-job scope needs the job's success; a step scope needs exactly that step's success, whatever an
    unrelated step of the same job did (a lint slip must not void a passed PostgreSQL suite)."""
    if step_name is None:
        return job.get("conclusion") == "success"
    steps = [step for step in job.get("steps", []) if step.get("name") == step_name]
    return len(steps) == 1 and steps[0].get("conclusion") == "success"


def release_evidence(sha: str, repo: str, gh: Callable[[str], Any] = _gh) -> dict[str, str]:
    """Per scope: ``reuse <run id>`` if a master run on exactly ``sha`` proved it, else ``run``."""
    answers: dict[str, str] = {}
    runs_by_workflow: dict[str, list[JSONObject]] = {}
    for scope, (workflow, job_names, step_name) in RELEASE_SCOPES.items():
        if workflow not in runs_by_workflow:
            listed = gh(
                f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&branch=master"
                f"&status=completed&per_page={_EVIDENCE_RUNS}"
            )["workflow_runs"]
            runs = sorted(
                (run for run in listed if run.get("head_sha") == sha and run.get("head_branch") == "master"),
                key=lambda run: int(run["id"]),
                reverse=True,
            )
            for run in runs:
                run["jobs"] = gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
            runs_by_workflow[workflow] = runs
        # The newest run that actually ran the scope decides: a later failure outweighs an earlier pass,
        # while a run that skipped the job (or lacks the step) says nothing either way.
        answers[scope] = "run"
        for run in runs_by_workflow[workflow]:
            ran = [job for job in run["jobs"] if job["name"] in job_names and _ran(job, step_name)]
            if ran:
                if all(_proof(job, step_name) for job in ran):
                    answers[scope] = f"reuse {run['id']}"
                break
    return answers


def pick_candidate(repo: str, gh: Callable[[str], Any] = _gh) -> str:
    """The newest master commit the queue vouched for and a nightly run proved in every release scope.

    An operator aid: dispatch the release candidate with the SHA this prints."""
    listed = gh(
        f"repos/{repo}/actions/workflows/{RELEASE_SCOPES['postgres'][0]}/runs?branch=master"
        f"&status=completed&per_page={_EVIDENCE_RUNS}"
    )["workflow_runs"]
    seen: set[str] = set()
    for run in sorted(listed, key=lambda run: int(run["id"]), reverse=True):
        sha = str(run.get("head_sha", ""))
        if run.get("head_branch") != "master" or sha in seen:
            continue
        seen.add(sha)
        if not all(answer.startswith("reuse ") for answer in release_evidence(sha, repo, gh).values()):
            continue
        try:
            verify(sha, repo, gh)
        except VerificationError:
            continue  # proven by the nightly, but the merge queue never vouched for it
        return sha
    raise VerificationError(
        "No recent master commit has nightly proof in every release scope; name a candidate SHA instead "
        "and the release candidate runs the missing scopes on it."
    )


def main(argv: list[str]) -> int:
    """``<sha>``: queue evidence, then per-scope decisions (written to $GITHUB_OUTPUT when set).
    ``--pick``: print the newest master commit with nightly proof in every scope."""
    if len(argv) != 2:
        print(f"usage: {argv[0]} <candidate-sha> | --pick", file=sys.stderr)
        return 2
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        if argv[1] == "--pick":
            print(pick_candidate(repo))
            return 0
        print(verify(argv[1], repo))
        answers = release_evidence(argv[1], repo)
    except (VerificationError, subprocess.CalledProcessError, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    for scope, answer in answers.items():
        print(f"{scope}: {answer}")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as handle:
            for scope, answer in answers.items():
                handle.write(f"{scope}={answer.split()[0]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
