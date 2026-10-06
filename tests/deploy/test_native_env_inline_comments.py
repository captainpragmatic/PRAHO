"""A native deploy must refuse a .env line that puts a comment after a value.

The native deploy copies the operator's `.env.<env>` to the server verbatim. That one file has several
readers, and they disagree on `KEY=value  # note`:

- python-dotenv (dev settings) and bash `source` end the value at ` #`. Compose interpolation does too.
- systemd `EnvironmentFile=`, which the praho-native units load, keeps the comment in the value.
  Checked on systemd 252: `DJANGO_SETTINGS_MODULE=config.settings.staging  # ← …` reaches the service
  whole, and Django fails with `No module named 'config.settings.staging  # ← …'`.
- The playbook's and the role's own parse (`grep` then `split('=', 1)`) keep it too, so
  `DB_USER=praho  # [OPTIONAL]` names the PostgreSQL role, and a required-variable check reads
  `KEY=   # note` as a value that is set.
- Quoting does not help when the comment follows the closing quote: systemd drops the quotes and keeps
  the rest, so `COMPANY_NAME="PragmaticHost SRL"  # note` arrives with the comment.

The fix moves every comment in the examples onto its own line, and the deploy refuses an inline comment
before anything reads the file. The check follows the shell's own rule: a `#` starts a comment only at the
start of a word and outside quotes, with backslash escapes honoured. These tests run the same script the
deploy runs, and check that the playbook and the role call it before their first read.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROLE = PROJECT_ROOT / "deploy/ansible/roles/praho-native"
CHECKER = ROLE / "files/check_env_inline_comments.py"
PLAYBOOK = PROJECT_ROOT / "deploy/ansible/playbooks/native-single-server.yml"
PREFLIGHT = "Reject inline comments in the .env file"


def _run(env_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # the deploy's own checker, on a file the test wrote
        [sys.executable, str(CHECKER), str(env_file)], capture_output=True, text=True, check=False
    )


def _check(tmp_path: Path, line: str) -> subprocess.CompletedProcess[str]:
    env_file = tmp_path / ".env"
    env_file.write_text(f"{line}\n")
    return _run(env_file)


def _names(tasks: list[dict[str, Any]]) -> list[str | None]:
    return [task.get("name") for task in tasks]


class TestTheCheckerFollowsTheShellCommentRule:
    @pytest.mark.integration
    @pytest.mark.parametrize(
        "line",
        [
            "DJANGO_SETTINGS_MODULE=config.settings.staging  # ← This is the key difference from prod",
            "DB_USER=praho                           # [OPTIONAL]",
            "DJANGO_SECRET_KEY=   # [REQUIRED] set me",
            "DJANGO_SECRET_KEY=# set me",
            "DB_PORT=5432\t# tab before the comment",
            "  DB_HOST=localhost # indented key",
            "DB_NAME=  praho # whitespace before the value",
            # systemd drops the quotes but keeps whatever follows the closing one
            'COMPANY_NAME="PragmaticHost SRL (STAGING)"  # [OPTIONAL]',
            "COMPANY_ADDRESS='Str. Exemplu Nr. 1' # single quotes",
            'DEFAULT_FROM_EMAIL="PRAHO <noreply@example.invalid>"# straight after the quote',
            # a value that continues after its quoted part, or holds an escaped quote
            'SITE_TITLE="foo"bar  # compound value',
            'SITE_TITLE="pa\\"ss"  # escaped quote',
            "SITE_TITLE=foo\\ bar # escaped space, then a comment",
            # systemd trims whitespace around the key, and joins a line ending in a backslash
            "DB_USER = praho  # spaced key",
            "DB_USER=praho\\\n  # database account",
        ],
    )
    def test_an_inline_comment_fails_the_deploy(self, tmp_path: Path, line: str) -> None:
        result = _check(tmp_path, line)
        key = line.strip().split("=", 1)[0].strip()
        assert result.returncode == 1, result.stdout + result.stderr
        assert f"1:{key}" in result.stdout.splitlines(), result.stdout

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "line",
        [
            "DB_USER=praho",
            "DJANGO_SECRET_KEY=",
            "# DB_USER=praho  # a commented-out line is not read",
            "",
            "BRANCH_NAME=feature#12",
            "SENTRY_DSN=https://example.invalid/#fragment",
            'HSTS_POLICY="max-age=3600; includeSubDomains # quoted"',
            "NOTE='quoted # value'",
            'NOTE="literal \\"#\\" marker"',
            "NOTE=foo\\#bar",
            "DB_USER = praho",
            "SHARE=C:\\\\",  # an escaped backslash ends the value; it does not continue the line
        ],
    )
    def test_a_value_without_an_inline_comment_passes(self, tmp_path: Path, line: str) -> None:
        result = _check(tmp_path, line)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout == ""

    @pytest.mark.integration
    def test_the_failure_names_keys_never_values(self, tmp_path: Path) -> None:
        value = secrets.token_urlsafe(16)
        result = _check(tmp_path, f"DB_PASSWORD={value}  # note")
        assert result.returncode == 1
        assert "1:DB_PASSWORD" in result.stdout.splitlines()
        assert value not in result.stdout + result.stderr

    @pytest.mark.integration
    def test_an_unreadable_file_fails_closed(self, tmp_path: Path) -> None:
        result = _run(tmp_path / "absent.env")
        assert result.returncode == 2, result.stdout + result.stderr

    @pytest.mark.integration
    def test_every_example_passes(self) -> None:
        examples = sorted(PROJECT_ROOT.glob(".env.example*"))
        # A broken glob must fail loudly, not check zero files and pass.
        assert len(examples) >= 3, examples
        for example in examples:
            result = _run(example)
            assert result.returncode == 0, f"{example.name}:\n{result.stdout}"


class TestTheDeployRunsTheCheckFirst:
    @pytest.mark.integration
    def test_the_preflight_task_runs_the_checker_on_the_env_file(self) -> None:
        tasks = yaml.safe_load((ROLE / "tasks/env_preflight.yml").read_text())
        argv = tasks[0]["command"]["argv"]
        assert argv == [
            "{{ ansible_playbook_python }}",
            "{{ role_path }}/files/check_env_inline_comments.py",
            "{{ env_file_path }}",
        ]
        assert tasks[0]["delegate_to"] == "localhost"

    @pytest.mark.integration
    def test_the_playbook_checks_before_its_first_read(self) -> None:
        pre_tasks = yaml.safe_load(PLAYBOOK.read_text())[0]["pre_tasks"]
        names = _names(pre_tasks)
        check = names.index(PREFLIGHT)
        assert pre_tasks[check]["include_role"] == {"name": "praho-native", "tasks_from": "env_preflight"}
        # After the existence check, before anything parses the file.
        assert names.index("Fail if .env file not found") < check < names.index("Read env vars for pre-flight validation")

    @pytest.mark.integration
    def test_the_role_checks_before_its_first_read(self) -> None:
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        names = _names(tasks)
        assert tasks[names.index(PREFLIGHT)]["include_tasks"] == "env_preflight.yml"
        assert names.index(PREFLIGHT) < names.index("Read .env file locally for role variables")
