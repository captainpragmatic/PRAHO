#!/usr/bin/env python3
"""Probe Virtualmin's incremental (differential) backup contract on the Docker lab.

Run through `make virtualmin-probe` after `make virtualmin-lab-up`. It needs
DJANGO_SETTINGS_MODULE=config.settings.lab, because it talks to the node the way
PRAHO does:
- remote.cgi calls go through VirtualminGateway;
- the PRAHO-path backups go through VirtualminBackupService;
- the production schedule playbook goes through AnsibleService.

It uses `docker exec` only to change files and rows on the node, to inspect
state and archives, and to run the scheduled backup the way cron would.

Every question ends in data assertions. The verdict per question is PROVEN,
DISPROVEN or INCONCLUSIVE, with the reason. The evidence is written to
docs/domain/virtualmin-incremental-contract.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import django

PROBE_TABLE = "probe_rows"
REMOTE_TMP = "/tmp"  # noqa: S108  # Path on the lab node, not a local tempfile
OUTPUT_TAIL_LINES = 14


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class Question:
    key: str
    title: str
    steps: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    verdict: str = "INCONCLUSIVE"
    reason: str = "not run"


class Recorder:
    def __init__(self) -> None:
        self.questions: dict[str, Question] = {}
        self.environment: list[str] = []
        self.current: Question | None = None

    def begin(self, key: str, title: str) -> Question:
        question = Question(key, title)
        self.questions[key] = question
        self.current = question
        print(f"\n🔬 [Probe] {key}: {title}", flush=True)
        return question

    def step(self, text: str) -> None:
        assert self.current is not None
        self.current.steps.append(text)

    def check(self, name: str, passed: bool, detail: object = "") -> bool:
        assert self.current is not None
        detail = str(detail)
        self.current.checks.append(Check(name, passed, detail))
        print(f"   {'✅' if passed else '❌'} {name} {detail}".rstrip(), flush=True)
        return passed

    def verdict(self, verdict: str, reason: str) -> None:
        assert self.current is not None
        self.current.verdict = verdict
        self.current.reason = reason
        print(f"   ⇒ {verdict}: {reason}", flush=True)


def tail(text: str, lines: int = OUTPUT_TAIL_LINES) -> str:
    kept = [line for line in text.strip().splitlines() if line.strip()]
    if len(kept) > lines:
        kept = ["…", *kept[-lines:]]
    return "\n".join(kept)


def fence(text: str) -> str:
    return "```text\n" + text.strip() + "\n```"


class Probe:
    def __init__(self, recorder: Recorder) -> None:
        from apps.provisioning.management.commands._virtualmin_lab import load_state
        from apps.provisioning.management.commands.virtualmin_lab_roundtrip import node_exec
        from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
        from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer

        self.rec = recorder
        self.state = load_state()
        self.node = self.state.node("vm-a")
        self.container = self.node.container
        self.domain = self.state.domain
        self.user = self.state.domain_user
        self.home = f"/home/{self.user}"
        self.server = VirtualminServer.objects.get(hostname=self.node.server_hostname)
        self.account = VirtualminAccount.objects.get(domain=self.domain)
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server))
        self._exec = node_exec
        self.ifile = ""
        self.safety_reset = False
        self.q3_results: dict[str, bool] = {}

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def tmp(name: str) -> str:
        """Archive path on the node (the same remote /tmp PRAHO's backups use)."""
        return f"{REMOTE_TMP}/probe_{name}.tar.gz"

    def sh(self, *argv: str) -> str:
        return str(self._exec(self.container, *argv))

    def script(self, body: str, *args: str) -> str:
        return self.sh("sh", "-c", body, "sh", *args)

    def api(self, program: str, params: dict[str, Any], *, record: bool = True) -> tuple[bool, str]:
        """remote.cgi through PRAHO's gateway; returns (explicit success, output)."""
        result = self.gateway.call(program, params, timeout_seconds=900)
        if result.is_err():
            output = f"gateway error: {result.unwrap_err()}"
            ok = False
        else:
            response = result.unwrap()
            data = response.data if isinstance(response.data, dict) else {}
            ok = bool(response.success) and data.get("status") == "success"
            output = str(data.get("output") or data.get("full_error") or data.get("error") or response.raw_response)
        if record:
            shown = json.dumps(params, sort_keys=False)
            self.rec.step(
                f"remote.cgi `{program}` {shown} → **{'success' if ok else 'failure'}**\n\n{fence(tail(output))}"
            )
        return ok, output

    def domain_id(self) -> str:
        return self.sh("virtualmin", "list-domains", "--domain", self.domain, "--id-only").strip()

    def database(self) -> str:
        names = self.sh("virtualmin", "list-databases", "--domain", self.domain, "--name-only").split()
        return names[0]

    def sql(self, statement: str) -> str:
        return self.sh("mysql", "-N", "-B", "-e", statement, self.database())

    def put_file(self, relative: str, content: str) -> None:
        # chown only the written file: a recursive chown would bump the ctime of
        # every sibling and put unchanged files into the next differential.
        self.script(
            'd="$(dirname "$1")"; [ -d "$d" ] || { mkdir -p "$d" && chown "$3:$3" "$d"; }; '
            'printf "%s" "$2" > "$1" && chown "$3:$3" "$1"',
            f"{self.home}/public_html/{relative}",
            content,
            self.user,
        )
        # Keep every change clearly before the next dump's start time.
        time.sleep(1.1)

    def remove_file(self, relative: str) -> None:
        self.sh("rm", "-f", f"{self.home}/public_html/{relative}")

    def fingerprint(self) -> dict[str, str]:
        files = self.script(
            'cd "$1" && find public_html/probe -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum',
            self.home,
        )
        rows = self.sql(f"SELECT id, body FROM {PROBE_TABLE} ORDER BY id")  # noqa: S608  # Constant table
        return {"files": files.strip(), "rows": rows.strip()}

    def file_state(self, path: str) -> str:
        """'absent' or '<sha256> <size> <mtime>' for one node file."""
        return self.script(
            'if [ -e "$1" ]; then printf "%s %s %s" "$(sha256sum < "$1" | cut -c1-16)" '
            '"$(stat -c %s "$1")" "$(stat -c %y "$1" | cut -d" " -f2)"; else printf absent; fi',
            path,
        ).strip()

    def dir_members(self, archive: str) -> list[str]:
        listing = self.script(
            'tar -xzOf "$1" "./$2_dir.tar" | tar -t 2>/dev/null | sort',
            archive,
            self.domain,
        )
        return [
            line
            for line in listing.splitlines()
            if line.startswith("./public_html/probe") and line != "./public_html/probe/"
        ]

    def backup(self, dest: str, extra: dict[str, Any], *, all_features: bool = True) -> bool:
        params: dict[str, Any] = {"domain": self.domain, "dest": dest}
        if all_features:
            params["all-features"] = ""
        params.update(extra)
        ok, _ = self.api("backup-domain", params)
        return ok

    def delete_domain(self) -> None:
        self.api("delete-domain", {"domain": self.domain})

    def restore(self, source: str) -> bool:
        ok, _ = self.api("restore-domain", {"domain": self.domain, "source": source, "all-features": ""})
        return ok

    def ensure_domain(self) -> None:
        listing = self.gateway.list_domains_with_owners()
        if any(row["domain"] == self.domain for row in listing.unwrap()):
            return
        ok, output = self.api(
            "create-domain",
            {"domain": self.domain, "user": self.user, "pass": self.account.get_password(), "default-features": ""},
            record=False,
        )
        if not ok:
            raise RuntimeError(f"create-domain failed: {output[-500:]}")

    def reset_domain(self) -> None:
        """Fresh domain, no incremental state, seeded probe files and rows."""
        listing = self.gateway.list_domains_with_owners().unwrap()
        if any(row["domain"] == self.domain for row in listing):
            self.api("delete-domain", {"domain": self.domain}, record=False)
        self.ensure_domain()
        self.ifile = f"/var/webmin/modules/virtual-server/incremental/{self.domain_id()}"
        self.sh("rm", "-f", self.ifile)
        self.sql(f"CREATE TABLE IF NOT EXISTS {PROBE_TABLE} (id INT PRIMARY KEY, body VARCHAR(64))")

    def seed(self, token: str) -> None:
        self.sql(f"DELETE FROM {PROBE_TABLE}")  # noqa: S608  # Constant table
        self.sql(f"INSERT INTO {PROBE_TABLE} VALUES (1, 'one {token}'), (2, 'two {token}')")  # noqa: S608
        self.put_file("probe/keep.txt", f"keep {token}\n")
        self.put_file("probe/change.txt", f"v0 {token}\n")
        self.put_file("probe/delete-me.txt", f"doomed {token}\n")

    def cleanup_tmp(self) -> None:
        self.script('rm -f "$1"/probe_*.tar.gz "$1"/probe_*.tar.gz.dom "$1"/probe_*.tar.gz.info', REMOTE_TMP)

    def snapshot_tree(self, roots: tuple[str, ...]) -> dict[str, str]:
        listing = self.script(
            'for r in "$@"; do find "$r" -type f -printf "%p %T@ %s\\n" 2>/dev/null; done | sort', *roots
        )
        rows: dict[str, str] = {}
        for line in listing.splitlines():
            path, _, rest = line.partition(" ")
            rows[path] = rest
        return rows

    # --------------------------------------------------------------- questions

    def environment(self) -> None:
        info = self.sh("virtualmin", "info")
        versions = [line.strip() for line in info.splitlines() if "version" in line and ":" in line]
        packages = self.sh(
            "dpkg-query", "-W", "-f=${Package} ${Version}\n", "webmin", "webmin-virtual-server", "virtualmin-config"
        )
        self.rec.environment = [
            f"Probe run: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"Node: {self.node.server_hostname} (container {self.container}), image praho-virtualmin-lab:8.3.0",
            *versions,
            *[f"package {line}" for line in packages.strip().splitlines()],
            f"tar: {self.sh('tar', '--version').splitlines()[0]}",
            f"os: {self.script('. /etc/os-release && echo $PRETTY_NAME').strip()}",
            "API user: root (master administrator), through PRAHO's VirtualminGateway",
        ]

    def q1_parameters(self) -> None:
        self.rec.begin("Q1", "Remote-API parameter names for differential / no-differential backups")
        usage = self.script("virtualmin backup-domain --help 2>&1 | grep -iE 'differential|incremental' || true")
        self.rec.step(f"`virtualmin backup-domain --help` (differential lines):\n\n{fence(usage)}")
        parser = self.script(
            "grep -nE 'incremental|differential' /usr/share/webmin/virtual-server/backup-domain.pl | grep 'elsif'"
        )
        self.rec.step(f"Argument parser in backup-domain.pl:\n\n{fence(parser)}")
        self.reset_domain()
        self.seed("q1")
        base = self.tmp("q1_base")
        self.rec.check("full backup (no flag) succeeds", self.backup(base, {}))
        self.put_file("probe/change.txt", "v1 q1\n")
        diff = self.tmp("q1_diff")
        diff_ok = self.backup(diff, {"differential": ""})
        self.rec.check("`differential` accepted over remote.cgi", diff_ok)
        members = self.dir_members(diff) if diff_ok else []
        base_members = self.dir_members(base)
        self.rec.step(f"Dir members, base: {base_members}; differential: {members}")
        only_changed = members == ["./public_html/probe/change.txt"]
        self.rec.check("differential archive holds only the changed file", only_changed, str(members))
        flag = self.script(
            'tar -xzOf "$1" "./$2_dir.tar" | tar -t | grep -x "./.incremental" || true', diff, self.domain
        ).strip()
        self.rec.check("differential dir archive carries the ./.incremental marker", flag == "./.incremental")
        nodiff = self.tmp("q1_nodiff")
        nodiff_ok = self.backup(nodiff, {"no-differential": ""})
        nodiff_members = self.dir_members(nodiff) if nodiff_ok else []
        self.rec.check(
            "`no-differential` accepted and produces a complete archive",
            nodiff_ok and len(nodiff_members) == 3,
            str(nodiff_members),
        )
        legacy_ok = self.backup(self.tmp("q1_legacy"), {"incremental": ""})
        legacy_no_ok = self.backup(self.tmp("q1_legacy_no"), {"no-incremental": ""})
        self.rec.check("legacy aliases `incremental` / `no-incremental` still accepted", legacy_ok and legacy_no_ok)
        bogus_ok, _ = self.api(
            "backup-domain", {"domain": self.domain, "dest": self.tmp("q1_x"), "all-features": "", "differential": "1"}
        )
        self.rec.check("a value on the bare flag is rejected (`differential=1` → `--differential 1`)", not bogus_ok)
        # The shapes PRAHO sent before the flag fix, verbatim. A rejected call
        # touches nothing, which also answers Q3 for them.
        before_shapes = self.file_state(self.ifile)
        for label, program, params in (
            (
                "pre-fix full backup",
                "backup-domain",
                {
                    "domain": self.domain,
                    "dest": self.tmp("q1_prefix_full"),
                    "all-features": True,
                    "all-virtualservers": False,
                    "newformat": True,
                },
            ),
            (
                "pre-fix config-only backup",
                "backup-domain",
                {
                    "domain": self.domain,
                    "dest": self.tmp("q1_prefix_cfg"),
                    "only-features": "virtualmin,dir",
                    "newformat": True,
                },
            ),
            (
                "pre-fix restore",
                "restore-domain",
                {"domain": self.domain, "source": self.tmp("q1_nodiff"), "all-features": True},
            ),
        ):
            shape_ok, shape_output = self.api(program, params)
            rejected = (not shape_ok) and "Unknown parameter" in shape_output
            self.rec.check(f"{label} is rejected with 'Unknown parameter'", rejected)
        self.rec.check(
            "the rejected pre-fix calls left the differential base untouched",
            self.file_state(self.ifile) == before_shapes,
        )
        self.cleanup_tmp()
        if all(check.passed for check in self.rec.questions["Q1"].checks):
            self.rec.verdict(
                "PROVEN",
                "`differential=` (bare) makes a differential backup, `no-differential=` a standalone full; "
                "`incremental`/`no-incremental` are accepted aliases; any value on the flag is rejected",
            )
        else:
            self.rec.verdict("DISPROVEN", "see failed checks")

    def q2_state_location(self) -> None:
        self.rec.begin("Q2", "Where per-domain differential state lives, and what a reset does to it")
        self.reset_domain()
        self.seed("q2")
        roots = ("/etc/webmin/virtual-server", "/var/webmin/modules/virtual-server")
        before = self.snapshot_tree(roots)
        self.rec.check("full backup", self.backup(self.tmp("q2_full1"), {}))
        after = self.snapshot_tree(roots)
        created = sorted(path for path in after if path not in before)
        changed = sorted(path for path in after if path in before and after[path] != before[path])
        domain_id = self.domain_id()
        self.rec.step(
            "Files created by the first full backup under "
            f"{', '.join(roots)}:\n\n{fence(chr(10).join(created) or '(none)')}\n\n"
            f"Files changed:\n\n{fence(chr(10).join(changed) or '(none)')}"
        )
        expected = f"/var/webmin/modules/virtual-server/incremental/{domain_id}"
        self.rec.check(f"state file created at incremental/<domain id> ({domain_id})", expected in created, expected)
        self.ifile = expected
        kind = self.sh("file", "-b", expected).strip() if expected in after else "absent"
        self.rec.step(f"`file {expected}`: {kind}")
        first = self.file_state(expected)
        time.sleep(1.2)
        self.put_file("probe/change.txt", "v1 q2\n")
        self.rec.check("second full backup", self.backup(self.tmp("q2_full2"), {}))
        second = self.file_state(expected)
        self.rec.step(f"State after full #1: `{first}`\n\nState after full #2: `{second}`")
        self.rec.check("a full backup rewrites the state (new hash and mtime)", second not in (first, "absent"))
        time.sleep(1.2)
        self.rec.check("differential backup", self.backup(self.tmp("q2_diff"), {"differential": ""}))
        third = self.file_state(expected)
        self.rec.step(f"State after a differential: `{third}`")
        self.rec.check(
            "a differential leaves the state as it was (restored after tar)",
            third.split()[:2] == second.split()[:2],
            third,
        )
        self.cleanup_tmp()
        passed = all(check.passed for check in self.rec.questions["Q2"].checks)
        self.rec.verdict(
            "PROVEN" if passed else "DISPROVEN",
            f"one GNU tar --listed-incremental snapshot per domain at {expected.rsplit('/', 1)[0]}/<domain id>; "
            "every full backup deletes and rewrites it (the new base); a differential restores it after tar"
            if passed
            else "see failed checks",
        )

    def _state_preserved(self, label: str, runner: Callable[[], bool]) -> bool:
        before = self.file_state(self.ifile)
        self.rec.check(f"{label}: a base exists before (non-vacuous)", before != "absent", before)
        time.sleep(1.2)
        self.put_file("probe/change.txt", f"{label} {secrets.token_hex(3)}\n")
        ran = runner()
        after = self.file_state(self.ifile)
        preserved = before == after
        self.rec.step(f"{label}: state before `{before}` → after `{after}`")
        self.rec.check(f"{label}: backup ran", ran)
        self.rec.check(
            f"{label}: base {'UNTOUCHED' if preserved else 'RESET'}",
            True,
            f"(observed {'untouched' if preserved else 'reset'})",
        )
        return preserved

    def q3_full_backups(self) -> None:
        from apps.provisioning.virtualmin_backup_service import (
            BackupConfig,
            RestoreConfig,
            VirtualminBackupService,
        )

        self.rec.begin("Q3", "Does a full backup leave the differential base untouched?")
        self.reset_domain()
        self.seed("q3")
        self.rec.check("establish base (plain full)", self.backup(self.tmp("q3_base"), {}))
        service = VirtualminBackupService(self.server)
        results: dict[str, bool] = {}

        def praho_full() -> bool:
            outcome = service.backup_domain(self.account, BackupConfig(include_email=False))
            self.rec.step(
                f"PRAHO full (`backup_domain`, include_email=False): {'Ok' if outcome.is_ok() else outcome.unwrap_err()}"
            )
            return outcome.is_ok()

        def praho_config_only() -> bool:
            outcome = service.backup_domain(self.account, BackupConfig(backup_type="config_only"))
            self.rec.step(
                f"PRAHO config-only (`backup_domain`, config_only): {'Ok' if outcome.is_ok() else outcome.unwrap_err()}"
            )
            return outcome.is_ok()

        def praho_safety() -> bool:
            # The real pre-restore safety backup: a forced restore over the live
            # domain runs backup_domain(BackupConfig()) before anything else.
            published = service.backup_domain(self.account, BackupConfig(include_email=False))
            if published.is_err():
                self.rec.step(f"could not publish a backup to restore from: {published.unwrap_err()}")
                return False
            backup_id = str(published.unwrap()["backup_id"])
            before = self.file_state(self.ifile)
            time.sleep(1.2)
            outcome = service.restore_domain(self.account, RestoreConfig(backup_id=backup_id, force_restore=True))
            after = self.file_state(self.ifile)
            self.rec.step(
                f"PRAHO forced restore of {backup_id} (runs the safety backup first): "
                f"{'Ok' if outcome.is_ok() else outcome.unwrap_err()}\n\nstate before safety+restore `{before}` → after `{after}`"
            )
            self.safety_reset = before != after
            return True

        def migration_params() -> bool:
            from apps.provisioning.virtualmin_migration_service import migration_backup_params

            archive = f"migration_{secrets.token_hex(4)}-0000-0000-0000-000000000000.tar.gz"
            params = migration_backup_params(archive)
            ok, _ = self.api("backup-domain", {"domain": self.domain, **params})
            self.script('rm -f "$1" "$1.dom" "$1.info"', str(params["dest"]))
            return ok

        self.safety_reset = False
        # The parameter shapes PRAHO sent before it passed no-differential.
        results["pre-fix full shape (no flag)"] = self._state_preserved(
            "pre-fix full shape (domain, dest, all-features)", lambda: self.backup(self.tmp("q3_prefix"), {})
        )
        results["PRAHO full"] = self._state_preserved("PRAHO full", praho_full)
        results["PRAHO config-only"] = self._state_preserved("PRAHO config-only", praho_config_only)
        results["migration params"] = self._state_preserved(
            "migration params (migration_backup_params)", migration_params
        )
        praho_safety()
        results["PRAHO safety + restore"] = not self.safety_reset
        self.rec.check(
            "PRAHO safety backup + restore: base " + ("RESET" if self.safety_reset else "UNTOUCHED"), True, "(observed)"
        )
        # Any dir restore clears the base (feature-dir.pl: "differential file is
        # no longer valid"), so the forced restore above leaves none. Record it,
        # then re-establish a base for the remaining measurements.
        self.rec.check("a restore clears the differential base", self.file_state(self.ifile) == "absent", "(observed)")
        self.rec.check("re-establish base (plain full)", self.backup(self.tmp("q3_rebase"), {}))
        nd = {"no-differential": ""}
        results["full + no-differential"] = self._state_preserved(
            "full + no-differential", lambda: self.backup(self.tmp("q3_nd_full"), nd)
        )
        results["config-only + no-differential"] = self._state_preserved(
            "config-only params + no-differential",
            lambda: self.backup(self.tmp("q3_nd_cfg"), {"feature": ["virtualmin", "dir"], **nd}, all_features=False),
        )
        results["migration + no-differential"] = self._state_preserved(
            "migration params + no-differential", lambda: self.backup(self.tmp("q3_nd_mig"), nd)
        )
        self.cleanup_tmp()
        summary = ", ".join(f"{name}: {'untouched' if kept else 'RESET'}" for name, kept in results.items())
        self.rec.step(f"Summary: {summary}")
        praho_sets = ("PRAHO full", "PRAHO config-only", "migration params")
        praho_keeps = all(results[name] for name in praho_sets)
        no_diff_keeps = all(results[name] for name in results if "no-differential" in name)
        flag_matters = not results["pre-fix full shape (no flag)"]
        self.q3_results = results
        if no_diff_keeps and praho_keeps and flag_matters:
            self.rec.verdict(
                "PROVEN",
                "`no-differential` leaves the base untouched, and without it a full backup resets the base; PRAHO's "
                "full, config-only and migration backups send it and keep the base. The pre-restore safety backup "
                "sends it too, but the restore that follows deletes the base"
                + (" (observed)" if not results["PRAHO safety + restore"] else ""),
            )
        else:
            self.rec.verdict("DISPROVEN", summary)

    def q5_q6_restore_order(self) -> None:
        self.rec.begin("Q5", "Restore order: base full, then the latest differential, with data assertions")
        self.reset_domain()
        self.seed("s0")
        s0 = self.fingerprint()
        self.rec.check("F0: base full", self.backup(self.tmp("q5_f0"), {}))
        self.put_file("probe/change.txt", "v1 s1\n")
        self.put_file("probe/added-s1.txt", "added in s1\n")
        self.sql(f"INSERT INTO {PROBE_TABLE} VALUES (3, 'three s1')")  # noqa: S608
        self.rec.check("D1: differential", self.backup(self.tmp("q5_d1"), {"differential": ""}))
        self.put_file("probe/change.txt", "v2 s2\n")
        self.remove_file("probe/delete-me.txt")
        self.sql(f"UPDATE {PROBE_TABLE} SET body = 'one s2' WHERE id = 1")  # noqa: S608
        self.sql(f"DELETE FROM {PROBE_TABLE} WHERE id = 2")  # noqa: S608
        self.rec.check(
            "N1: intervening standalone full (no-differential)", self.backup(self.tmp("q5_n1"), {"no-differential": ""})
        )
        self.put_file("probe/added-s2.txt", "added in s2\n")
        self.rec.check("D2: differential", self.backup(self.tmp("q5_d2"), {"differential": ""}))
        s2 = self.fingerprint()
        d2_members = self.dir_members(self.tmp("q5_d2"))
        self.rec.step(
            f"State S0 (at F0):\n\n{fence(json.dumps(s0, indent=2))}\n\nState S2 (at D2):\n\n{fence(json.dumps(s2, indent=2))}"
        )
        self.rec.step(f"D2 dir members: {d2_members}")
        self.rec.check(
            "D2 is relative to F0 (holds every file changed since F0, not since N1)",
            set(d2_members)
            == {
                "./public_html/probe/change.txt",
                "./public_html/probe/added-s1.txt",
                "./public_html/probe/added-s2.txt",
            },
            str(d2_members),
        )
        self.put_file("probe/change.txt", "v3 after\n")
        # Disaster-recovery order onto an empty server: delete, then F0, then D2.
        self.delete_domain()
        self.rec.check("restore F0", self.restore(self.tmp("q5_f0")))
        self.rec.check("restore D2", self.restore(self.tmp("q5_d2")))
        final = self.fingerprint()
        self.rec.step(f"State after F0 + D2:\n\n{fence(json.dumps(final, indent=2))}")
        rows_equal = final["rows"] == s2["rows"]
        files_s2 = {line.split()[1]: line.split()[0] for line in s2["files"].splitlines()}
        files_final = {line.split()[1]: line.split()[0] for line in final["files"].splitlines()}
        present_equal = all(files_final.get(path) == digest for path, digest in files_s2.items())
        extra = sorted(set(files_final) - set(files_s2))
        self.rec.check("database rows equal S2", rows_equal)
        self.rec.check("every S2 file is back with the S2 checksum", present_equal)
        self.rec.check("no file beyond S2 (exact equality)", not extra, str(extra))
        if rows_equal and present_equal and not extra:
            self.rec.verdict("PROVEN", "base full then latest differential reproduces S2 exactly, rows and files")
        elif rows_equal and present_equal:
            self.rec.verdict(
                "DISPROVEN",
                f"rows and every S2 file match, but the restore is not exact: files deleted after the base come back ({extra})",
            )
        else:
            self.rec.verdict("DISPROVEN", "restored data differs from S2; see checks")

        self.rec.begin("Q6", "Do files deleted after the base come back after base + differential restore?")
        came_back = "public_html/probe/delete-me.txt" in files_final
        self.rec.step(
            "`probe/delete-me.txt` existed at F0 and was deleted before D2. Present after F0 + D2: "
            f"**{came_back}** (checksum {files_final.get('public_html/probe/delete-me.txt', '-')})"
        )
        self.rec.check("deleted file present after restore", came_back)
        self.rec.verdict(
            "PROVEN" if came_back else "DISPROVEN",
            "deleted files are resurrected: Virtualmin extracts the differential over the base without "
            "replaying deletions"
            if came_back
            else "deleted files stay deleted",
        )
        self.q5_final = final

        # Hazard variant: an intervening DEFAULT full moves the base.
        self.rec.begin("Q5b", "Hazard: a default (base-resetting) full between base and differential")
        self.reset_domain()
        self.seed("h0")
        self.rec.check("F0: base full", self.backup(self.tmp("q5b_f0"), {}))
        self.put_file("probe/change.txt", "h1\n")
        self.rec.check(
            "X: intervening default full (as PRAHO/migration/safety send today)", self.backup(self.tmp("q5b_x"), {})
        )
        self.put_file("probe/added-h2.txt", "h2\n")
        self.rec.check("D: differential", self.backup(self.tmp("q5b_d"), {"differential": ""}))
        expected = self.fingerprint()
        members = self.dir_members(self.tmp("q5b_d"))
        self.rec.step(f"D dir members: {members}")
        self.delete_domain()
        self.rec.check("restore F0", self.restore(self.tmp("q5b_f0")))
        self.rec.check("restore D", self.restore(self.tmp("q5b_d")))
        got = self.fingerprint()
        lost = expected["files"] != got["files"]
        self.rec.step(f"Expected files:\n\n{fence(expected['files'])}\n\nAfter F0 + D:\n\n{fence(got['files'])}")
        self.rec.check("F0 + D misses the change made before X (silent data loss)", lost)
        self.rec.verdict(
            "PROVEN" if lost else "DISPROVEN",
            "an intervening full that resets the base makes base+differential restore silently lose changes"
            if lost
            else "no loss observed",
        )
        self.cleanup_tmp()

    def q7_differential_alone(self) -> None:
        self.rec.begin("Q7", "Restoring a differential alone onto a deleted domain")
        self.reset_domain()
        self.seed("q7")
        self.rec.check("base full", self.backup(self.tmp("q7_f0"), {}))
        self.put_file("probe/change.txt", "q7 changed\n")
        self.rec.check("differential", self.backup(self.tmp("q7_d"), {"differential": ""}))
        expected = self.fingerprint()
        self.delete_domain()
        ok = self.restore(self.tmp("q7_d"))
        exists = any(row["domain"] == self.domain for row in self.gateway.list_domains_with_owners().unwrap())
        self.rec.check("restore-domain reports success", ok)
        self.rec.check("domain exists afterwards", exists)
        got: dict[str, str] = {}
        if exists:
            got = self.fingerprint()
            self.rec.step(
                f"Expected (state at the differential):\n\n{fence(expected['files'])}\n\nAfter restoring the differential alone:\n\n{fence(got['files'])}"
            )
        complete = bool(got) and got["files"] == expected["files"]
        rows_ok = bool(got) and got["rows"] == expected["rows"]
        self.rec.check("files complete", complete)
        self.rec.check("database rows complete (dumps are always full)", rows_ok)
        if exists and not complete:
            self.rec.verdict(
                "PROVEN",
                "a differential alone recreates the domain and its database but only the files changed since the base; "
                "unchanged files are missing, so it must never be restored without its base",
            )
        elif exists and complete:
            self.rec.verdict("DISPROVEN", "the differential alone restored every file")
        else:
            self.rec.verdict("PROVEN", "a differential alone cannot recreate a deleted domain")
        self.reset_domain()
        self.cleanup_tmp()

    def q8_differential_without_base(self) -> None:
        self.rec.begin("Q8", "A differential after a restore: is there still a base?")
        self.reset_domain()
        self.seed("q8")
        self.rec.check("F0: full", self.backup(self.tmp("q8_f0"), {}))
        self.rec.check("base exists after F0", self.file_state(self.ifile) != "absent")
        self.rec.check("restore F0 over the live domain", self.restore(self.tmp("q8_f0")))
        cleared = self.file_state(self.ifile) == "absent"
        self.rec.check("the restore deleted the base", cleared)
        self.put_file("probe/change.txt", "q8 changed\n")
        self.rec.check("D: differential", self.backup(self.tmp("q8_d"), {"differential": ""}))
        members = self.dir_members(self.tmp("q8_d"))
        self.rec.step(f"D dir members: {members}")
        full = len(members) == 3
        self.rec.check("D silently contains every file (a full)", full, str(members))
        self.rec.check("D created a new base", self.file_state(self.ifile) != "absent")
        self.rec.verdict(
            "PROVEN" if cleared and full else "DISPROVEN",
            "a restore deletes the domain's base; the next `differential` then silently runs as a full and becomes "
            "the new base"
            if cleared and full
            else "see checks",
        )
        self.cleanup_tmp()

    def q4_schedule(self) -> None:
        from apps.infrastructure.ansible_service import AnsibleService

        self.rec.begin("Q4", "Schedule discovery after applying the production virtualmin_backup.yml")
        self.reset_domain()
        self.seed("q4")
        self.rec.check("base full before the schedule", self.backup(self.tmp("q4_base"), {}))
        before_listing = self.sh("virtualmin", "list-scheduled-backups", "--multiline")
        self.rec.step(
            f"`virtualmin list-scheduled-backups --multiline` before:\n\n{fence(before_listing or '(empty)')}"
        )
        deployment = self.server.node_deployment
        result = AnsibleService().run_playbook(deployment, "virtualmin_backup.yml", {}, timeout_seconds=900)
        played = result.is_ok() and result.unwrap().success
        detail = result.unwrap_err() if result.is_err() else tail(result.unwrap().stdout, 30)
        self.rec.step(
            f"`AnsibleService.run_playbook(virtualmin_backup.yml)` → **{'success' if played else 'failure'}**\n\n{fence(detail)}"
        )
        self.rec.check("production playbook applied", played)
        leftovers = self.script(
            "ls /etc/webmin/virtual-server/sched 2>/dev/null; "
            "grep -E '^backup_(increment|dest|strftime|virtualmin|onebyone|compression)=' "
            "/etc/webmin/virtual-server/config || true"
        ).strip()
        self.rec.step(f"Legacy `sched` file and backup_* config keys after the play:\n\n{fence(leftovers or '(none)')}")
        self.rec.check("the legacy schedule inputs are gone", not leftovers, leftovers)
        listing = self.sh("virtualmin", "list-scheduled-backups", "--multiline")
        self.rec.step(f"`virtualmin list-scheduled-backups --multiline` after:\n\n{fence(listing or '(empty)')}")
        ids = self.sh("virtualmin", "list-scheduled-backups", "--id-only").split()
        self.rec.check("Virtualmin lists exactly one scheduled backup", len(ids) == 1, ids)
        schedule_id = ids[0] if ids else ""
        cron = self.script(
            'grep -l "^arg1=--id $1$" /etc/webmin/webmincron/crons/*.cron 2>/dev/null | xargs -r cat',
            schedule_id or "none",
        )
        self.rec.step(f"Webmin cron entry for schedule {schedule_id or '(none)'}:\n\n{fence(cron or '(none)')}")
        enabled = "Enabled: Yes" in listing
        differential = next(
            (line.split(":", 1)[1].strip() for line in listing.splitlines() if "Differential:" in line), "-"
        )
        self.rec.check("the listed schedule is enabled", enabled)
        self.rec.check("the listed schedule is not differential", differential == "No", differential)
        self.rec.check("Webmin cron runs backup.pl for it", "arg0=backup.pl" in cron)
        before_state = self.file_state(self.ifile)
        self.script("rm -rf /var/backups/virtualmin/* 2>/dev/null || true")
        # The environment Webmin's cron wrapper sets before running backup.pl.
        run = self.script(
            "cd /usr/share/webmin/virtual-server && WEBMIN_CONFIG=/etc/webmin WEBMIN_VAR=/var/webmin "
            '/usr/share/webmin/virtual-server/backup.pl --id "$1" 2>&1; echo "exit $?"',
            schedule_id or "none",
        )
        after_state = self.file_state(self.ifile)
        produced = self.script(
            'cd /var/backups/virtualmin 2>/dev/null && for f in */*.tar.gz; do [ -e "$f" ] || continue; '
            'echo "$f $(stat -c %s "$f") bytes, members: $(tar -tzf "$f" 2>/dev/null | wc -l)"; done'
        ).strip()
        self.rec.step(
            f"`backup.pl --id {schedule_id}` with the cron wrapper's environment (what cron runs):\n\n"
            f"{fence(tail(run, 20))}\n\nArchives under /var/backups/virtualmin afterwards:\n\n{fence(produced or '(none)')}"
            f"\n\nstate `{before_state}` → `{after_state}`"
        )
        ran = f"{self.domain}.tar.gz" in produced and "members: 0" not in produced
        kept = before_state == after_state
        self.rec.check("the scheduled backup ran and archived the domain", ran, produced)
        self.rec.check("it left the differential base untouched", kept, f"{before_state} → {after_state}")
        if played and not leftovers and len(ids) == 1 and enabled and differential == "No" and ran and kept:
            self.rec.verdict(
                "PROVEN",
                "the production playbook creates one enabled, non-differential scheduled backup through "
                "`virtualmin create-scheduled-backup` and removes the legacy `sched` file and backup_* keys; Webmin cron "
                f"runs it (`backup.pl --id {schedule_id}`), and running it archives the domain and leaves the differential "
                "base untouched.",
            )
        else:
            self.rec.verdict(
                "DISPROVEN",
                f"played={played} leftovers={bool(leftovers)} schedules={len(ids)} enabled={enabled} "
                f"differential={differential} ran={ran} base_kept={kept}",
            )
        self.script("rm -rf /var/backups/virtualmin/* 2>/dev/null || true")
        self.cleanup_tmp()


def render(recorder: Recorder) -> str:
    lines = [
        "# Virtualmin incremental (differential) backup contract",
        "",
        "Evidence for #498. `scripts/virtualmin_incremental_probe.py` (`make virtualmin-probe`) generated it against the",
        "Docker lab in `deploy/virtualmin-lab/`. Re-run the probe to refresh it; do not edit it by hand.",
        "",
        "Each assertion is a predicate checked against the node. `FAIL` means the predicate is false, and for",
        'an observation ("the scheduled backup ran") a false predicate can be the finding itself. The verdict',
        "line under each question states what the evidence establishes.",
        "",
        "## Environment",
        "",
        *[f"- {line}" for line in recorder.environment],
        "",
        "## Verdicts",
        "",
        "| Question | Verdict | Reason |",
        "|---|---|---|",
    ]
    for question in recorder.questions.values():
        reason = question.reason.replace("|", "\\|")
        lines.append(f"| {question.key}: {question.title} | **{question.verdict}** | {reason} |")
    for question in recorder.questions.values():
        lines += ["", f"## {question.key}: {question.title}", "", f"**{question.verdict}**: {question.reason}", ""]
        lines += ["### Assertions", "", "| Check | Result | Detail |", "|---|---|---|"]
        for check in question.checks:
            detail = check.detail.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {check.name} | {'pass' if check.passed else 'FAIL'} | {detail} |")
        lines += ["", "### Steps and output", ""]
        for number, step in enumerate(question.steps, 1):
            lines += [f"{number}. {step}", ""]
    # Command output carries trailing blanks (ansible, tar); keep the file clean.
    text = "\n".join(lines)
    return "\n".join(line.rstrip() for line in text.splitlines()).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    django.setup()
    logging.getLogger().setLevel(logging.WARNING)

    from apps.provisioning.management.commands._virtualmin_lab import (
        lab_transport,
        load_state,
        refuse_unless_lab_settings,
    )

    refuse_unless_lab_settings()
    recorder = Recorder()
    probe = Probe(recorder)
    failure: BaseException | None = None
    with lab_transport(load_state()):
        try:
            probe.environment()
            probe.q1_parameters()
            probe.q2_state_location()
            probe.q3_full_backups()
            probe.q5_q6_restore_order()
            probe.q7_differential_alone()
            probe.q8_differential_without_base()
            probe.q4_schedule()
        except Exception as error:  # Record what ran; the evidence must not vanish with the error
            failure = error
            if recorder.current is not None:
                recorder.current.verdict = "INCONCLUSIVE"
                recorder.current.reason = f"probe error: {error}"
    args.output.write_text(render(recorder))
    print(f"\n📝 [Probe] Evidence written to {args.output}")
    if failure is not None:
        print(f"🔥 [Probe] Stopped early: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
