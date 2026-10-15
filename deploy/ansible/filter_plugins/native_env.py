"""Serialize the same decoded values for native management commands and systemd."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from native_env import systemd_env


class FilterModule:
    def filters(self) -> dict[str, Callable[[dict[str, str]], str]]:
        return {"native_systemd_env": systemd_env}
