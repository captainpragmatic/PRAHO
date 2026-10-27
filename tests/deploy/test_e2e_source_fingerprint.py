"""An untracked directory symlink is source metadata, not a directory to read as a file."""

import importlib.util
from pathlib import Path
from unittest.mock import patch


def test_fingerprint_tracks_symlink_target_without_reading_external_directory(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[2] / "scripts/e2e_stack.py"
    spec = importlib.util.spec_from_file_location("status_e2e_stack", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "external-venv"
    target.mkdir()
    link = tmp_path / ".venv-darwin"
    link.symlink_to(target, target_is_directory=True)
    with patch.object(module, "ROOT", tmp_path), patch.object(module.subprocess, "check_output", side_effect=lambda args, **_kwargs: b".venv-darwin\0" if "ls-files" in args else b"fixture-tree"):
        first = module.source_fingerprint()
        (target / "runtime-file").write_text("runtime contents are not repository source")
        assert module.source_fingerprint() == first
        link.unlink()
        link.symlink_to(tmp_path / "another-runtime", target_is_directory=True)
        assert module.source_fingerprint() != first
    assert first["dirty"] is True
