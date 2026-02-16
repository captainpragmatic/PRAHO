import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ruff_new_violations.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ruff_new_violations", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {SCRIPT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def completed(args, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr=stderr)


def test_resolve_changed_files_uses_requested_baseline(monkeypatch):
    module = load_module()

    def fake_run_git(args, *, check=True):
        assert check is False
        assert args == ["diff", "--name-only", "base-sha...HEAD"]
        return completed(args, stdout="a.py\nb.txt\n")

    monkeypatch.setattr(module, "run_git", fake_run_git)
    files, effective_baseline = module.resolve_changed_files_for_baseline("base-sha")

    assert files == ["a.py", "b.txt"]
    assert effective_baseline == "base-sha"


def test_resolve_changed_files_falls_back_to_head_parent(monkeypatch):
    module = load_module()
    calls = []

    def fake_run_git(args, *, check=True):
        calls.append(args)
        if args == ["diff", "--name-only", "missing-sha...HEAD"]:
            return completed(args, returncode=128, stderr="fatal: bad revision")
        if args == ["rev-parse", "--verify", "--quiet", "HEAD~1^{commit}"]:
            return completed(args, returncode=0)
        if args == ["diff", "--name-only", "HEAD~1...HEAD"]:
            return completed(args, returncode=0, stdout="services/platform/foo.py\nREADME.md\n")
        raise AssertionError(f"Unexpected git call: {args}")

    monkeypatch.setattr(module, "run_git", fake_run_git)
    files, effective_baseline = module.resolve_changed_files_for_baseline("missing-sha")

    assert files == ["services/platform/foo.py", "README.md"]
    assert effective_baseline == "HEAD~1"
    assert calls[0] == ["diff", "--name-only", "missing-sha...HEAD"]


def test_resolve_changed_files_falls_back_to_head_tree_when_no_parent(monkeypatch):
    module = load_module()

    def fake_run_git(args, *, check=True):
        if args == ["diff", "--name-only", "missing...HEAD"]:
            return completed(args, returncode=128, stderr="fatal: bad revision")
        if args == ["rev-parse", "--verify", "--quiet", "HEAD~1^{commit}"]:
            return completed(args, returncode=1)
        if args == ["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"]:
            return completed(args, returncode=0, stdout="bootstrap.py\n")
        raise AssertionError(f"Unexpected git call: {args}")

    monkeypatch.setattr(module, "run_git", fake_run_git)
    files, effective_baseline = module.resolve_changed_files_for_baseline("missing")

    assert files == ["bootstrap.py"]
    assert effective_baseline is None


def test_collect_python_candidates_returns_effective_baseline(monkeypatch):
    module = load_module()

    def fake_resolve(baseline_ref):
        assert baseline_ref == "missing"
        return ["a.py", "a.py", "notes.txt", "services/platform/b.py"], "HEAD~1"

    monkeypatch.setattr(module, "resolve_changed_files_for_baseline", fake_resolve)
    candidates, effective_baseline = module.collect_python_candidates(
        explicit_paths=[],
        staged=False,
        since=None,
        baseline_ref="missing",
        path_prefixes=["services/platform"],
    )

    assert candidates == ["services/platform/b.py"]
    assert effective_baseline == "HEAD~1"


def test_build_baseline_tree_skips_when_effective_baseline_is_none(tmp_path):
    module = load_module()
    baseline_files = module.build_baseline_tree(
        files=["a.py"],
        baseline_ref=None,
        baseline_root=tmp_path / "baseline",
    )
    assert baseline_files == []
