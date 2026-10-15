"""Runs the pair restore node script (praho-pair-restore.sh) against a fake node in CI.

What is proved here is the ordering and the barrier: a maintenance host and disable-domain are up
before the first restore and re-applied after each one; every archive is verified before it is
restored; a cancel marker stops the pair between its two restores with the barrier still up; a
barrier that cannot be verified refuses before anything destructive and leaves the node as it was.
The lab proves the same against a real Apache and Virtualmin.
"""

from __future__ import annotations

import hashlib
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from django.conf import settings
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_pair_restore import PairStepResult, parse_pair_step_result
from tests.provisioning.test_virtualmin_chain_node_script import _SHIMS as CHAIN_SHIMS
from tests.provisioning.test_virtualmin_chain_playbook import TOKEN

SCRIPT = Path(settings.BASE_DIR) / "infrastructure" / "ansible" / "playbooks" / "files" / "praho-pair-restore.sh"
DOMAIN = "node.example.com"
DOMAIN_ID = "17919754553303"
BASE = "virtualmin_backup_" + "b" * 32 + ".tar.gz"
DIFF = "virtualmin_backup_" + "d" * 32 + ".tar.gz"

_PAIR_SHIMS = {
    "virtualmin": r"""#!/bin/bash
state=$FAKE_STATE
cmd=$1; shift
case $cmd in
  list-domains)
    mode=name
    for a in "$@"; do case $a in --id-only) mode=id ;; --disabled) mode=disabled ;; --multiline) mode=multi ;; esac; done
    case $mode in
      id) echo "$FAKE_DOMAIN_ID" ;;
      disabled) if [[ -e $state/disabled ]]; then echo "$FAKE_DOMAIN"; fi ;;
      multi)
        echo "    IP address: 10.9.8.7 (Shared)"
        [[ ${FAKE_NO_DOCROOT:-0} == 1 ]] || echo "    HTML directory: ${FAKE_DOCROOT:-/home/node/public_html}"
        echo "    Website hostnames: ${FAKE_HOSTNAMES-$FAKE_DOMAIN www.$FAKE_DOMAIN mail.$FAKE_DOMAIN}"
        ;;
      name) if [[ ${FAKE_DOMAIN_GONE:-0} != 1 ]]; then echo "$FAKE_DOMAIN"; fi ;;
    esac
    ;;
  disable-domain) echo disable >>"$state/calls"; : >"$state/disabled" ;;
  enable-domain)
    echo enable >>"$state/calls"
    if [[ ${FAKE_ENABLE_FAILS:-0} != 1 ]]; then rm -f "$state/disabled"; fi
    ;;
  restore-domain)
    source=""
    while (($#)); do case $1 in --source) source=$2; shift ;; esac; shift; done
    n=$(($(cat "$state/restore_count" 2>/dev/null || echo 0) + 1)); echo $n >"$state/restore_count"
    {
      printf 'restore %s source=%s ' "$n" "$(basename "$source")"
      [[ -e $state/disabled ]] && printf 'disabled=yes ' || printf 'disabled=no '
      [[ -e $PRAHO_APACHE_DIR/zz-praho-maint-$FAKE_DOMAIN_ID.conf ]] && printf 'maint=yes\n' || printf 'maint=no\n'
    } >>"$state/calls"
    cp "$PRAHO_APACHE_DIR/zz-praho-maint-$FAKE_DOMAIN_ID.conf" "$state/maint.$n.conf" 2>/dev/null || true
    if [[ ${FAKE_RESTORE_ENABLES:-0} == 1 ]]; then rm -f "$state/disabled"; fi
    if [[ ${FAKE_RESTORE_FAIL_ON:-0} == "$n" ]]; then echo "restore blew up" >&2; exit 1; fi
    if [[ ${FAKE_CANCEL_AFTER:-0} == "$n" ]]; then : >"$PRAHO_RUN_DIR/chain-$FAKE_DOMAIN_ID.cancelled.$FAKE_TOKEN"; fi
    ;;
esac
""",
    # 503 while the maintenance include exists, 200 otherwise; FAKE_NO_503 simulates a barrier that never takes.
    # Every probed host is recorded; FAKE_OPEN_HOST names one spelling the barrier does not cover.
    "curl": r"""#!/bin/bash
host=""
while (($#)); do case $1 in --resolve) host=${2%%:*}; shift ;; esac; shift; done
echo "$host" >>"$FAKE_STATE/probed"
if [[ -n ${FAKE_OPEN_HOST:-} && $host == "$FAKE_OPEN_HOST" ]]; then printf 200; exit 0; fi
if [[ -n ${FAKE_OPEN_AFTER_RESTORE:-} && -e $FAKE_STATE/restore_count && $host == "$FAKE_OPEN_AFTER_RESTORE" ]]; then printf 200; exit 0; fi
if [[ ${FAKE_NO_503:-0} != 1 && -e $PRAHO_APACHE_DIR/zz-praho-maint-$FAKE_DOMAIN_ID.conf ]]; then printf 503; else printf 200; fi
""",
    "apache2ctl": (
        "#!/bin/bash\n"
        'if [[ $1 == -M ]]; then [[ ${FAKE_SSL:-1} == 1 ]] && echo " ssl_module (shared)"; exit 0; fi\n'
        'echo "$1" >>"$FAKE_STATE/apache"\n'
    ),
    "openssl": (
        "#!/bin/bash\n"
        'while (($#)); do case $1 in -out) printf pem >"$2"; shift ;; esac; shift; done\n'
    ),
}


class PairRestoreScriptTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.bin, self.staging, self.run_dir, self.apache, self.state = (
            self.root / name for name in ("bin", "staging", "run", "apache", "state")
        )
        for directory in (self.bin, self.staging, self.apache, self.state):
            directory.mkdir()
        self.staging.chmod(0o700)
        for name, body in {**CHAIN_SHIMS, **_PAIR_SHIMS}.items():
            shim = self.bin / name
            shim.write_text(body)
            shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        self.shas: dict[str, str] = {}
        for name, content in ((BASE, b"base-bytes"), (DIFF, b"diff-bytes")):
            (self.staging / name).write_bytes(content)
            self.shas[name] = hashlib.sha256(content).hexdigest()
        self.maint = self.apache / f"zz-praho-maint-{DOMAIN_ID}.conf"

    def run_script(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "PRAHO_PAIR_ACTION": "restore",
            "PRAHO_DOMAIN": DOMAIN,
            "PRAHO_DOMAIN_ID": DOMAIN_ID,
            "PRAHO_CHAIN_TOKEN": TOKEN,
            "PRAHO_LOCK_WAIT": "1",
            "PRAHO_STAGING_DIR": str(self.staging),
            "PRAHO_BASE_ARCHIVE": BASE,
            "PRAHO_DIFF_ARCHIVE": DIFF,
            "PRAHO_BASE_SHA": self.shas[BASE],
            "PRAHO_DIFF_SHA": self.shas[DIFF],
            "PRAHO_RUN_DIR": str(self.run_dir),
            "PRAHO_APACHE_DIR": str(self.apache),
            "FAKE_STATE": str(self.state),
            "FAKE_DOMAIN": DOMAIN,
            "FAKE_DOMAIN_ID": DOMAIN_ID,
            "FAKE_TOKEN": TOKEN,
            **overrides,
        }
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False)  # noqa: S603  # Fixed argv

    def step(self, action: str = "restore", **overrides: str) -> PairStepResult:
        completed = self.run_script(PRAHO_PAIR_ACTION=action, **overrides)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        parsed = parse_pair_step_result(completed.stdout, token=TOKEN, domain_id=DOMAIN_ID, action=action)
        self.assertTrue(parsed.is_ok(), parsed)
        return parsed.unwrap()

    def calls(self) -> list[str]:
        path = self.state / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def restores(self) -> list[str]:
        return [line for line in self.calls() if line.startswith("restore ")]

    def disabled(self) -> bool:
        return (self.state / "disabled").exists()

    def test_both_layers_are_up_before_the_first_restore_and_the_domain_ends_disabled(self) -> None:
        result = self.step()
        self.assertEqual((result.outcome, result.ran), ("ok", True))
        first, second = self.restores()
        self.assertIn(f"source={BASE} disabled=yes maint=yes", first)
        self.assertIn(f"source={DIFF} disabled=yes maint=yes", second)
        self.assertEqual(
            [c.step for c in result.checkpoints], ["barrier_up", "after_base", "after_differential", "barrier_down"]
        )
        self.assertIsNone(result.barrier_broken())
        for checkpoint in result.checkpoints[:-1]:
            self.assertEqual((checkpoint.disabled, checkpoint.http80, checkpoint.http443), (True, "503", "503"))
        self.assertTrue(self.disabled(), "enabling the domain again belongs to reconcile, never to the script")
        self.assertNotIn("enable", self.calls())
        self.assertFalse(self.maint.exists(), "the maintenance host comes down only after verification")

    def test_a_restore_that_re_enables_the_domain_is_put_back_and_verified(self) -> None:
        result = self.step(FAKE_RESTORE_ENABLES="1")
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(self.calls().count("disable"), 3, "once for the barrier, once after each restore")
        self.assertTrue(all(c.disabled for c in result.checkpoints))

    def test_a_stop_between_the_restores_keeps_both_layers_and_reports_where_it_stopped(self) -> None:
        result = self.step(FAKE_CANCEL_AFTER="1")
        self.assertEqual((result.outcome, result.reason, result.ran), ("failed", "cancelled_before_differential", True))
        self.assertEqual(len(self.restores()), 1, "the differential was never restored")
        self.assertEqual([c.step for c in result.checkpoints], ["barrier_up", "after_base"])
        self.assertTrue(self.disabled())
        self.assertTrue(self.maint.exists(), "the maintenance host stays up until an operator releases it")
        self.assertTrue(result.checkpoints[-1].barrier_holds)

    def test_a_failed_restore_keeps_both_layers(self) -> None:
        for failing, steps in ((1, ["barrier_up", "base_failed"]), (2, ["barrier_up", "after_base", "differential_failed"])):
            with self.subTest(failing_restore=failing):
                self.state_reset()
                result = self.step(FAKE_RESTORE_FAIL_ON=str(failing))
                self.assertEqual((result.outcome, result.ran), ("failed", True))
                self.assertEqual([c.step for c in result.checkpoints], steps)
                self.assertTrue(self.disabled() and self.maint.exists())

    def test_a_barrier_that_cannot_be_verified_refuses_before_anything_destructive(self) -> None:
        result = self.step(FAKE_NO_503="1")
        self.assertEqual((result.outcome, result.reason, result.ran), ("refused", "barrier_not_verified", False))
        self.assertEqual(self.restores(), [])
        self.assertFalse(self.maint.exists())
        self.assertFalse(self.disabled(), "a refusal leaves the node as it was, including the enabled state")

    def maintenance_conf(self) -> str:
        """The 503 section as it stood while the first restore ran."""
        return (self.state / "maint.1.conf").read_text()

    def probed(self) -> list[str]:
        return (self.state / "probed").read_text().split()

    def test_the_barrier_is_keyed_on_the_virtual_host_and_on_every_spelling_of_its_names(self) -> None:
        self.step(
            FAKE_DOCROOT="/home/node/public_html",
            FAKE_HOSTNAMES=f"{DOMAIN} www.{DOMAIN} shop.{DOMAIN} *.wild.{DOMAIN}",
        )
        conf = self.maintenance_conf()
        self.assertIn("RewriteOptions InheritDownBefore", conf, "it runs before the virtual host's own rewrite rules")
        self.assertIn("RewriteCond %{DOCUMENT_ROOT} ^/home/node/public_html(/|$) [OR]", conf, "keyed on the vhost")
        host_condition = next(line for line in conf.splitlines() if line.startswith("RewriteCond %{HTTP_HOST}"))
        self.assertTrue(host_condition.endswith("[NC]"), "the host comparison ignores case")
        self.assertIn(r")\.?(:[0-9]+)?$", host_condition, "an optional trailing dot and port are allowed")
        for alias in (r"node\.example\.com", r"www\.node", r"mail\.node", r"shop\.node"):
            self.assertIn(alias, host_condition)
        self.assertIn(r"[A-Za-z0-9.-]+\.wild\.node\.example\.com", host_condition, "a wildcard alias is covered")
        self.assertIn("RewriteRule ^ - [R=503,L]", conf)

    def test_every_odd_spelling_of_the_domains_names_is_probed_at_every_checkpoint(self) -> None:
        result = self.step(FAKE_HOSTNAMES=f"{DOMAIN} www.{DOMAIN} shop.{DOMAIN}")
        probed = set(self.probed())
        for host in (DOMAIN.upper(), f"{DOMAIN}.", f"mail.{DOMAIN}", f"www.{DOMAIN}", f"shop.{DOMAIN}"):
            self.assertIn(host, probed)
        for checkpoint in result.checkpoints[:-1]:
            self.assertEqual(checkpoint.odd_hosts, "503", checkpoint.step)

    def test_a_spelling_the_barrier_does_not_cover_refuses_before_anything_destructive(self) -> None:
        for host in (DOMAIN.upper(), f"{DOMAIN}.", f"mail.{DOMAIN}"):
            with self.subTest(host=host):
                self.state_reset()
                result = self.step(FAKE_OPEN_HOST=host)
                self.assertEqual((result.outcome, result.reason, result.ran), ("refused", "barrier_not_verified", False))
                self.assertEqual(result.checkpoints[0].odd_hosts, "200")
                self.assertEqual(self.restores(), [])
                self.assertFalse(self.maint.exists())

    def test_a_spelling_that_slips_through_after_a_restore_keeps_the_barrier_and_fails(self) -> None:
        # The first checkpoint is clean; the host opens only once the base restore has run.
        result = self.step(FAKE_OPEN_AFTER_RESTORE=DOMAIN.upper())
        self.assertEqual((result.outcome, result.reason, result.ran), ("failed", "barrier_lost_after_after_base", True))
        self.assertEqual(len(self.restores()), 1, "the differential was never restored")
        self.assertEqual(result.checkpoints[-1].odd_hosts, "200")
        self.assertTrue(self.maint.exists() and self.disabled(), "both layers stay up for an operator")

    def test_a_domain_whose_document_root_is_unknown_is_refused_untouched(self) -> None:
        result = self.step(FAKE_NO_DOCROOT="1")
        self.assertEqual((result.outcome, result.reason, result.ran), ("refused", "docroot_unknown", False))
        self.assertFalse((self.state / "apache").exists(), "Apache was never touched")
        self.assertFalse(self.disabled())

    def test_a_refusal_whose_undo_cannot_enable_the_domain_says_it_is_left_disabled(self) -> None:
        result = self.step(FAKE_NO_503="1", FAKE_ENABLE_FAILS="1")
        self.assertEqual((result.outcome, result.reason, result.ran), ("failed", "barrier_undo_incomplete", True))
        self.assertEqual(self.restores(), [])
        self.assertTrue(self.disabled(), "the node really is left disabled")
        self.assertFalse(self.maint.exists(), "the maintenance section was taken down")

    def test_an_archive_that_does_not_match_its_checksum_is_refused_before_the_barrier(self) -> None:
        (self.staging / DIFF).write_bytes(b"tampered")
        result = self.step()
        self.assertEqual((result.outcome, result.reason, result.ran), ("refused", "archive_not_verified", False))
        self.assertEqual(self.restores(), [])
        self.assertFalse((self.state / "apache").exists(), "Apache was never touched")
        self.assertFalse(self.disabled())

    def test_a_cancelled_token_never_starts(self) -> None:
        self.step("release")
        refused = self.step()
        self.assertEqual((refused.outcome, refused.reason, refused.ran), ("refused", "cancelled", False))
        self.assertEqual(self.restores(), [])

    def test_release_takes_the_maintenance_host_down_and_leaves_the_domain_disabled(self) -> None:
        self.step(FAKE_CANCEL_AFTER="1")
        released = self.step("release")
        self.assertEqual((released.outcome, released.ran), ("released", False))
        self.assertFalse(self.maint.exists())
        self.assertTrue(self.disabled())
        self.assertTrue((self.run_dir / f"chain-{DOMAIN_ID}.cancelled.{TOKEN}").exists())

    def test_a_domain_id_that_is_not_this_domains_is_refused(self) -> None:
        result = self.step(FAKE_DOMAIN_ID="999")
        self.assertEqual((result.outcome, result.reason, result.ran), ("refused", "domain_id_mismatch", False))

    def test_inputs_are_validated(self) -> None:
        cases = {
            "PRAHO_DOMAIN": "example.com-",
            "PRAHO_BASE_ARCHIVE": "../etc/passwd",
            "PRAHO_BASE_SHA": "nope",
            "PRAHO_DIFF_ARCHIVE": BASE,  # the same archive twice is not a pair
            "PRAHO_APACHE_DIR": "relative/dir",
            "PRAHO_RUN_DIR": f"{self.root}/../escape",
            "PRAHO_STEP_HOLD": "999",
        }
        for name, bad in cases.items():
            with self.subTest(name=name):
                completed = self.run_script(**{name: bad})
                self.assertEqual(completed.returncode, 64)
                self.assertNotIn("PAIR_RESULT", completed.stdout)

    def state_reset(self) -> None:
        for path in self.state.iterdir():
            path.unlink()
        self.maint.unlink(missing_ok=True)

    def test_the_result_parser_rejects_a_line_for_another_run(self) -> None:
        completed = self.run_script()
        other: Any = parse_pair_step_result(
            completed.stdout, token="1c2d3e4f-0000-4000-8000-000000000001", domain_id=DOMAIN_ID, action="restore"
        )
        self.assertTrue(other.is_err())
