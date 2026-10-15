"""Load native configuration in-process, without printing credentials to a subprocess stream."""

from __future__ import annotations

import sys
from pathlib import Path

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from native_env import pgpass, read_env, systemd_env


class LookupModule(LookupBase):
    def run(
        self, terms: list[str], variables: dict[str, object] | None = None, **kwargs: object
    ) -> list[dict[str, object]]:
        try:
            values = read_env(Path(terms[0]))
        except (OSError, UnicodeError, ValueError):
            raise AnsibleError(
                "Invalid native env file; run the native launcher to see sanitized line/key diagnostics"
            ) from None
        return [{"env": values, "systemd": systemd_env(values), "pgpass": pgpass(values)}]
