"""Where the developer `.env` lives, if the settings run from the repo at all.

Dev settings load the repo-root `.env` when they run from `services/<service>/config/settings/`. In the
Docker dev image the same files sit at `/app/config/settings/`, with no repo root above them; the
container gets its environment from Compose instead. Kept identical in platform and portal (a test
pins it), because the portal cannot import platform code.
"""

from __future__ import annotations

from pathlib import Path


def repo_dotenv_path(settings_file: Path) -> Path | None:
    """The repo-root `.env` for a settings module inside the repo layout, or None.

    Only `<root>/services/<service>/config/settings/<module>.py` counts as the repo layout, so a
    shallow container path (or any other deep path that merely has enough parents) finds nothing.
    """
    parents = settings_file.resolve().parents
    if len(parents) <= 4 or parents[3].name != "services":  # noqa: PLR2004  # settings, config, <service>, services
        return None
    candidate = parents[4] / ".env"
    return candidate if candidate.is_file() else None
