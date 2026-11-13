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

import base64
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


# The native acceptance shards (scripts/run_native_acceptance.py): together they run every case once.
NATIVE_PROFILES = ("split-prod-1", "split-prod-2", "split-prod-3", "split-prod-4", "combined-staging", "combined-prod")

# A release scope -> (workflow, the job-name sets that can prove it, the step that proves it, or None for the
# whole job). One run must hold every job of one set; a matrix names its jobs after the matrix value.
# The nightly matrix names its job after the branch it tested; only master's counts.
RELEASE_SCOPES: dict[str, tuple[str, tuple[frozenset[str], ...], str | None]] = {
    "postgres": ("nightly.yml", (frozenset({"nightly (master)"}),), "Whole platform suite on PostgreSQL"),
    # make test-integration collects tests/deploy, CrowdSec's Docker qualification among them.
    "crowdsec": ("nightly.yml", (frozenset({"nightly (master)"}),), "Integration tests"),
    # Every shard, or the single job of a nightly from before the shards.
    "native": (
        "nightly.yml",
        (
            frozenset(f"nightly-native-deploy ({profile})" for profile in NATIVE_PROFILES),
            frozenset({"nightly-native-deploy"}),
        ),
        None,
    ),
    # "nightly-full" is the container lab's name before node deploy moved to native acceptance.
    "lab": ("virtualmin-lab.yml", (frozenset({"nightly-containers"}), frozenset({"nightly-full"})), None),
}
_EVIDENCE_RUNS = 100  # runs of one workflow on one commit; a full page is treated as truncated history
# Step evidence from nightly.yml counts only when that commit's own nightly.yml checks out the run's exact
# commit (a scheduled run uses the workflow file at its head_sha). Before this pin, the master leg checked
# out the branch name, which can be a later commit than the one the run is credited to.
NIGHTLY_CHECKOUT_PIN = "ref: ${{ matrix.branch == 'master' && github.sha || matrix.branch }}"


def _nightly_pinned(sha: str, repo: str, gh: Callable[[str], Any]) -> bool:
    try:
        content = gh(f"repos/{repo}/contents/.github/workflows/nightly.yml?ref={sha}")
    except subprocess.CalledProcessError:
        return False
    text = base64.b64decode(content.get("content", "")).decode("utf-8", errors="replace")
    return NIGHTLY_CHECKOUT_PIN in text


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


def _covers(run: JSONObject, names: frozenset[str], step_name: str | None) -> bool:
    """Whether one run proved every job of ``names``. For a matrix set, the run's jobs of that matrix must be
    exactly the expected ones: a shard the verifier does not expect means the lists drifted apart."""
    passed = {job["name"] for job in run["jobs"] if job["name"] in names and _proof(job, step_name)}
    if not names <= passed:
        return False
    if len(names) > 1:
        bases = {name.split(" (", 1)[0] for name in names}
        family = {job["name"] for job in run["jobs"] if job["name"].split(" (", 1)[0] in bases}
        return family == names
    return True


def release_evidence(sha: str, repo: str, gh: Callable[[str], Any] = _gh) -> dict[str, str]:
    """Per scope: ``reuse <run id>`` if a master run on exactly ``sha`` proved it, else ``run``."""
    answers: dict[str, str] = {}
    runs_by_workflow: dict[str, list[JSONObject]] = {}
    pinned: bool | None = None
    for scope, (workflow, job_sets, step_name) in RELEASE_SCOPES.items():
        job_names = frozenset().union(*job_sets)
        if workflow == "nightly.yml" and step_name is not None:
            if pinned is None:
                pinned = _nightly_pinned(sha, repo, gh)
            if not pinned:
                answers[scope] = "run"
                continue
        if workflow not in runs_by_workflow:
            # Every status: a re-run still in progress holds its failed earlier attempt.
            listed = gh(
                f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&branch=master&per_page={_EVIDENCE_RUNS}"
            )["workflow_runs"]
            runs = sorted(
                (run for run in listed if run.get("head_sha") == sha and run.get("head_branch") == "master"),
                key=lambda run: int(run["id"]),
                reverse=True,
            )
            # A full page may hide an older failure beyond it: no reuse from a truncated history.
            truncated = len(listed) >= _EVIDENCE_RUNS
            # A run not yet finished on this commit proves nothing and may yet fail: no reuse until it ends.
            truncated = truncated or any(run.get("status", "completed") != "completed" for run in runs)
            for run in runs:
                # filter=all: a failed earlier attempt of a re-run must count too.
                page = gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=all&per_page=100")
                run["jobs"] = page["jobs"]
                # More jobs than one page: a failed attempt may be on a page not read.
                truncated = truncated or int(page.get("total_count", len(run["jobs"]))) > len(run["jobs"])
            runs_by_workflow[workflow] = [] if truncated else runs
        # Monotone: reuse only if every execution of the scope on this commit passed. Any failure on the
        # commit, in any run or re-run, means `run`; no timestamp order decides. A run that skipped the job
        # (or lacks the step) says nothing either way. And one run must have proven a whole job set: shards
        # from two runs, or a run that ran fewer shards, prove nothing.
        executed = [
            (run, job)
            for run in runs_by_workflow[workflow]
            for job in run["jobs"]
            if job["name"] in job_names and _ran(job, step_name)
        ]
        covering = [
            run for run in runs_by_workflow[workflow] if any(_covers(run, names, step_name) for names in job_sets)
        ]
        proven = bool(executed) and all(_proof(job, step_name) for _run, job in executed) and bool(covering)
        answers[scope] = f"reuse {covering[0]['id']}" if proven else "run"
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
        # Outside Actions (a local --pick), gh fills {owner}/{repo} from this checkout's remote.
        repo = os.environ.get("GITHUB_REPOSITORY") or "{owner}/{repo}"
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
