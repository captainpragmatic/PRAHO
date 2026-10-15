"""Runs the node script (praho-chain-backup.sh) against a fake Virtualmin in a temporary directory.

The lab proves the script against a real node; these tests prove its decisions in CI, on any
host. The directories it works in are validated overrides, and the few system tools it needs that
differ across hosts or need root (flock, sha256sum, GNU stat, install -o root) are replaced by
shims on PATH, so macOS and Linux behave identically. The fake `virtualmin` writes an archive and
moves the differential snapshot the way the real one does: a plain full backup replaces it, a
differential leaves it alone.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from django.test import SimpleTestCase

from apps.provisioning import virtualmin_backup_service as backup_service
from tests.provisioning.test_virtualmin_chain_playbook import SCRIPT, TOKEN

DOMAIN = "node.example.com"
DOMAIN_ID = "17919754553303"
ARCHIVE = "virtualmin_backup_" + "e" * 32 + ".tar.gz"
OTHER_TOKEN = "1c2d3e4f-0000-4000-8000-000000000001"

_SHIMS = {
    # A held lock is simulated by FAKE_LOCK_HELD=1; there is no real flock on every host.
    "flock": '#!/bin/bash\n[[ ${FAKE_LOCK_HELD:-0} == 1 ]] && exit 1\nexit 0\n',
    "sha256sum": (
        "#!/bin/bash\n"
        'args=("$@"); [[ ${args[0]:-} == -- ]] && args=("${args[@]:1}")\n'
        "if [[ -x /usr/bin/sha256sum ]]; then exec /usr/bin/sha256sum \"${args[@]}\"; fi\n"
        'exec /usr/bin/shasum -a 256 "${args[@]}"\n'
    ),
    # Only the two forms the script uses; the owner is always reported as root.
    "stat": (
        "#!/bin/bash\n"
        'fmt=$2; target=$4\n'
        'case $fmt in\n'
        '  %s) wc -c <"$target" | tr -d " " ;;\n'
        "  %u:%a) mode=$(/usr/bin/stat -c %a \"$target\" 2>/dev/null || /usr/bin/stat -f %Lp \"$target\"); echo \"0:$mode\" ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n"
    ),
    # Drops -o/-g (they need root) and copes with /dev/null as a source on any host.
    "install": (
        "#!/bin/bash\n"
        'args=(); skip=0; mode=""\n'
        'for a in "$@"; do\n'
        "  if ((skip)); then skip=0; continue; fi\n"
        '  case $a in -o|-g) skip=1 ;; *) args+=("$a") ;; esac\n'
        "done\n"
        "for ((i = 0; i < ${#args[@]}; i++)); do\n"
        '  [[ ${args[i]} == -m ]] && mode=${args[i+1]}\n'
        '  if [[ ${args[i]} == /dev/null ]]; then dest=${args[${#args[@]}-1]}; : >"$dest"; chmod "${mode:-0600}" "$dest"; exit 0; fi\n'
        "done\n"
        'exec /usr/bin/install "${args[@]}"\n'
    ),
    # list-domains answers FAKE_DOMAIN_ID; backup-domain writes the archive and moves the snapshot.
    "virtualmin": (
        "#!/bin/bash\n"
        "cmd=$1; shift\n"
        "case $cmd in\n"
        '  list-domains) printf "%s\\n" "$FAKE_DOMAIN_ID" ;;\n'
        "  backup-domain)\n"
        '    dest=""; differential=0\n'
        '    while (($#)); do\n'
        '      case $1 in --dest) dest=$2; shift ;; --differential) differential=1 ;; esac\n'
        "      shift\n"
        "    done\n"
        '    if [[ ${FAKE_BACKUP_FAIL:-0} == 1 ]]; then echo "disk full" >&2; exit 3; fi\n'
        '    printf "archive-bytes\\n" >"$dest"; printf "DBPASSWORD\\n" >"$dest.dom"\n'
        "    if ((differential)); then\n"
        '      if [[ ${FAKE_DIFFERENTIAL_MOVES_SNAPSHOT:-0} == 1 ]]; then printf "moved-%s\\n" "$RANDOM$$" >"$FAKE_SNAPSHOT"; fi\n'
        '    elif [[ ${FAKE_BASE_KEEPS_SNAPSHOT:-0} != 1 ]]; then\n'
        '      printf "snapshot-%s\\n" "$RANDOM$RANDOM$$" >"$FAKE_SNAPSHOT"\n'
        "    fi\n"
        "    ;;\n"
        "esac\n"
    ),
}


class ChainNodeScriptTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.bin, self.snapshots, self.run_dir, self.staging = (
            self.root / name for name in ("bin", "snapshots", "run", "staging")
        )
        for directory in (self.bin, self.snapshots, self.staging):
            directory.mkdir()
        self.staging.chmod(0o700)
        for name, body in _SHIMS.items():
            shim = self.bin / name
            shim.write_text(body)
            shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        self.snapshot = self.snapshots / DOMAIN_ID

    def run_script(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "PRAHO_CHAIN_ACTION": "run",
            "PRAHO_CHAIN_MODE": "base",
            "PRAHO_DOMAIN": DOMAIN,
            "PRAHO_DOMAIN_ID": DOMAIN_ID,
            "PRAHO_CHAIN_TOKEN": TOKEN,
            "PRAHO_ARCHIVE": ARCHIVE,
            "PRAHO_LOCK_WAIT": "1",
            "PRAHO_STAGING_DIR": str(self.staging),
            "PRAHO_SNAPSHOT_DIR": str(self.snapshots),
            "PRAHO_RUN_DIR": str(self.run_dir),
            "FAKE_DOMAIN_ID": DOMAIN_ID,
            "FAKE_SNAPSHOT": str(self.snapshot),
            **overrides,
        }
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False)  # noqa: S603  # Fixed argv

    def step(self, mode: str = "base", **overrides: str) -> Any:
        """Run the script and decode its one result line, as the controller does."""
        completed = self.run_script(PRAHO_CHAIN_MODE=mode, **overrides)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        parsed = backup_service.parse_chain_step_result(
            completed.stdout,
            token=overrides.get("PRAHO_CHAIN_TOKEN", TOKEN),
            mode="cancel" if overrides.get("PRAHO_CHAIN_ACTION") == "cancel" else mode,
            domain_id=DOMAIN_ID,
        )
        self.assertTrue(parsed.is_ok(), parsed)
        return parsed.unwrap()

    def fingerprint(self) -> str:
        data = self.snapshot.read_bytes()
        return f"{hashlib.sha256(data).hexdigest()}:{len(data)}"

    def new_archive(self) -> str:
        return "virtualmin_backup_" + os.urandom(16).hex() + ".tar.gz"

    def test_a_base_reads_the_snapshot_before_and_after_and_vouches_for_the_archive(self) -> None:
        first = self.step("base")
        self.assertEqual((first.outcome, first.ran, first.fp_before), ("ok", True, "ABSENT"))
        self.assertEqual(first.fp_after, self.fingerprint())
        archive = self.staging / ARCHIVE
        self.assertEqual(first.sha256, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(first.size, archive.stat().st_size)
        self.assertFalse((self.run_dir / f"chain-{DOMAIN_ID}.running").exists(), "the running marker is removed")
        second = self.step("base", PRAHO_ARCHIVE=self.new_archive())
        self.assertEqual(second.fp_before, first.fp_after)
        self.assertNotEqual(second.fp_after, second.fp_before, "a second base resets the snapshot again")

    def test_a_differential_with_the_matching_fingerprint_leaves_the_snapshot_untouched(self) -> None:
        base = self.step("base")
        differential = self.step("differential", PRAHO_ARCHIVE=self.new_archive(), PRAHO_EXPECTED_FP=base.fp_after)
        self.assertEqual((differential.outcome, differential.ran), ("ok", True))
        self.assertEqual((differential.fp_before, differential.fp_after), (base.fp_after, base.fp_after))

    def test_a_differential_with_a_stale_fingerprint_runs_nothing(self) -> None:
        self.step("base")
        archive = self.new_archive()
        refused = self.step("differential", PRAHO_ARCHIVE=archive, PRAHO_EXPECTED_FP="f" * 64 + ":1")
        self.assertEqual((refused.outcome, refused.reason, refused.ran), ("refused", "fingerprint_mismatch", False))
        self.assertEqual(refused.fp_before, self.fingerprint())
        self.assertFalse((self.staging / archive).exists(), "no backup was started")

    def test_a_differential_cannot_expect_an_absent_snapshot(self) -> None:
        completed = self.run_script(PRAHO_CHAIN_MODE="differential", PRAHO_EXPECTED_FP="ABSENT")
        self.assertEqual(completed.returncode, 64)
        self.assertNotIn("CHAIN_RESULT", completed.stdout)
        self.assertFalse((self.staging / ARCHIVE).exists())

    def test_a_differential_that_moves_the_snapshot_is_discarded_with_its_sidecar(self) -> None:
        base = self.step("base")
        archive = self.new_archive()
        failed = self.step(
            "differential",
            PRAHO_ARCHIVE=archive,
            PRAHO_EXPECTED_FP=base.fp_after,
            FAKE_DIFFERENTIAL_MOVES_SNAPSHOT="1",
        )
        self.assertEqual((failed.outcome, failed.reason, failed.ran), ("failed", "snapshot_changed", True))
        self.assertNotEqual(failed.fp_after, failed.fp_before)
        self.assertEqual(list(self.staging.glob(archive + "*")), [], "the archive and its .dom sidecar are gone")

    def test_a_base_that_did_not_reset_the_snapshot_is_discarded(self) -> None:
        self.step("base")
        archive = self.new_archive()
        failed = self.step("base", PRAHO_ARCHIVE=archive, FAKE_BASE_KEEPS_SNAPSHOT="1")
        self.assertEqual((failed.outcome, failed.reason), ("failed", "snapshot_not_reset"))
        self.assertEqual(list(self.staging.glob(archive + "*")), [])

    def test_a_failed_backup_command_is_reported_and_leaves_nothing_behind(self) -> None:
        failed = self.step("base", FAKE_BACKUP_FAIL="1")
        self.assertEqual((failed.outcome, failed.reason, failed.backup_rc), ("failed", "backup_command_failed", 3))
        self.assertIn("disk full", failed.detail)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_a_cancelled_token_never_starts_but_another_token_does(self) -> None:
        cancelled = self.step(PRAHO_CHAIN_ACTION="cancel")
        self.assertEqual((cancelled.outcome, cancelled.reason), ("cancelled", "marker_written"))
        self.assertTrue((self.run_dir / f"chain-{DOMAIN_ID}.cancelled.{TOKEN}").exists())
        refused = self.step("base")
        self.assertEqual((refused.outcome, refused.reason, refused.ran), ("refused", "cancelled", False))
        self.assertFalse((self.staging / ARCHIVE).exists())
        other = self.step("base", PRAHO_CHAIN_TOKEN=OTHER_TOKEN)
        self.assertEqual((other.outcome, other.ran), ("ok", True))

    def test_a_held_lock_refuses_without_running(self) -> None:
        refused = self.step("base", FAKE_LOCK_HELD="1")
        self.assertEqual((refused.outcome, refused.reason, refused.ran), ("refused", "lock_busy", False))

    def test_a_domain_id_that_is_not_this_domains_refuses(self) -> None:
        refused = self.step("base", FAKE_DOMAIN_ID="999")
        self.assertEqual((refused.outcome, refused.reason, refused.ran), ("refused", "domain_id_mismatch", False))

    def test_the_working_directories_are_validated_overrides(self) -> None:
        for name in ("PRAHO_RUN_DIR", "PRAHO_SNAPSHOT_DIR"):
            for bad in ("relative/dir", f"{self.root}/../escape", f"{self.root}/with space", ""):
                with self.subTest(name=name, value=bad):
                    completed = self.run_script(**{name: bad} if bad else {name: " "})
                    self.assertEqual(completed.returncode, 64)
                    self.assertNotIn("CHAIN_RESULT", completed.stdout)

    def test_other_inputs_are_still_validated(self) -> None:
        for name, bad in (
            ("PRAHO_DOMAIN", "example.com-"),
            ("PRAHO_DOMAIN_ID", "12a"),
            ("PRAHO_CHAIN_TOKEN", "not-a-uuid"),
            ("PRAHO_ARCHIVE", "../etc/passwd"),
            ("PRAHO_CHAIN_MODE", "full"),
        ):
            with self.subTest(name=name):
                self.assertEqual(self.run_script(**{name: bad}).returncode, 64)
