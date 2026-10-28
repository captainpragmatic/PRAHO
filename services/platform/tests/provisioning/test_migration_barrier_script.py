"""Runs the migration's write barrier (praho-write-barrier.sh) against a fake node.

The fake behaves as the lab found Virtualmin and MariaDB (plan amendment E2): disable-domain comments
the owner's jobs and makes each vhost serve the disabled page; a locked account is refused; an open
Webmin session lives in an SDBM store the reload re-reads. What is proved: the fence on administration
comes before the accounts are counted and locked; the barrier holds only when every write path is
closed; a release restores exactly what was recorded and is verified against the record; the crontab
never leaves the node; a cancel marker and a held lock stop an action before it starts. The lab proves
the same against a real node.
"""

from __future__ import annotations

import base64
import json
import signal
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_virtualmin_chain_node_script import _SHIMS as CHAIN_SHIMS
from tests.provisioning.test_virtualmin_pair_restore_script import _PAIR_SHIMS as PAIR_SHIMS

SCRIPT = Path(settings.BASE_DIR) / "infrastructure" / "ansible" / "playbooks" / "files" / "praho-write-barrier.sh"
DOMAIN = "shop.example.com"
CHILD = "h7k3p2q8.praho-sites.net"  # The account name: a sub-server of DOMAIN
DOMAIN_ID = "17919754553303"
TOKEN = "11111111-2222-4333-8444-555555555555"
PREVIOUS = "99999999-2222-4333-8444-555555555555"
OWNER = "shop"
EXTRA = f"app@{DOMAIN}"
DB = "shop"
CRONTAB = "MAILTO=owner@example.com\n# nightly\n0 3 * * * /home/shop/bin/report\n*/5 * * * * /home/shop/bin/queue\n"

_SHIMS = {
    "virtualmin": r"""#!/bin/bash
state=$FAKE_STATE
cmd=$1; shift
want=""; prev=""; for a in "$@"; do [[ $prev != --domain ]] || want=$a; prev=$a; done
vhost() { printf '<VirtualHost 10.0.0.1:80>\n    ServerName %s\n</VirtualHost>\n<VirtualHost 10.0.0.1:443>\n    ServerName %s\n</VirtualHost>\n' "$1" "$1" >"$PRAHO_APACHE_SITES/$1.conf"; }
case $cmd in
  list-domains)
    mode=name
    for a in "$@"; do case $a in --disabled) mode=disabled ;; --multiline) mode=multi ;; --parent) mode=children ;; esac; done
    case $mode in
      children) [[ -z ${FAKE_CHILD:-} ]] || echo "$FAKE_CHILD" ;;
      disabled) for n in "$FAKE_DOMAIN" ${FAKE_CHILD:-}; do [[ ! -e $state/disabled.$n ]] || echo "$n"; done ;;
      multi)
        echo "    Username: $FAKE_OWNER"
        echo "    Username for mysql: $FAKE_OWNER"
        echo "    Password for mysql: owner-db-pass"
        features="unix dir web ssl logrotate mysql webmin"; [[ ${FAKE_MAIL_ON:-} != "$want" ]] || features+=" mail"
        echo "    Features: $features"
        if [[ ${FAKE_DELAY_FEATURE_TRAILER:-0} == 1 ]]; then /bin/sleep 0.05; echo "    Description: native listing trailer"; fi ;;
      name) echo "$FAKE_DOMAIN" ;;
    esac ;;
  list-databases) echo "$FAKE_DB" ;;
  list-users)
    for u in ${FAKE_DB_USERS:-}; do echo "$u"; echo "    Unix username: $u"; echo "    Databases: $FAKE_DB (mysql)"; done ;;
  disable-domain)
    echo "disable $want $*" >>"$state/calls"
    targets=("$want"); if [[ " $* " == *" --subservers "* && -n ${FAKE_CHILD:-} && ${FAKE_CHILD_IGNORES_DISABLE:-0} != 1 ]]; then targets+=("$FAKE_CHILD"); fi
    for t in "${targets[@]}"; do
      [[ ! -e $state/disabled.$t ]] || continue
      : >"$state/disabled.$t"
      n=2; [[ ${FAKE_ONE_VHOST_OPEN:-0} != 1 ]] || n=1
      for ((i = 0; i < n; i++)); do printf '    AliasMatch ^/.*$ %s/disabled_by_virtualmin.html\n' "$FAKE_PAGE_DIR" >>"$PRAHO_APACHE_SITES/$t.conf"; done
    done
    if [[ $want == "$FAKE_DOMAIN" && -e $state/crontab && ${FAKE_DISABLE_LEAVES_JOB:-0} != 1 ]]; then
      sed -E 's/^([^#].*)$/# \1 # VIRTUALMIN DISABLE/' "$state/crontab" >"$state/crontab.new" && mv "$state/crontab.new" "$state/crontab"
    fi ;;
  enable-domain)
    echo "enable $want" >>"$state/calls"
    targets=("$want"); if [[ " $* " == *" --subservers "* && $want == "$FAKE_DOMAIN" && -n ${FAKE_CHILD:-} ]]; then targets+=("$FAKE_CHILD"); fi
    for t in "${targets[@]}"; do
      rm -f "$state/disabled.$t"
      grep -v AliasMatch "$PRAHO_APACHE_SITES/$t.conf" >"$PRAHO_APACHE_SITES/$t.new"; mv "$PRAHO_APACHE_SITES/$t.new" "$PRAHO_APACHE_SITES/$t.conf"
    done
    if [[ $want == "$FAKE_DOMAIN" && -e $state/crontab && ${FAKE_ENABLE_STRANDS_CRON:-0} != 1 ]]; then
      sed -E 's/^# (.*) # VIRTUALMIN DISABLE$/\1/' "$state/crontab" >"$state/crontab.new" && mv "$state/crontab.new" "$state/crontab"
    fi ;;
esac
""",
    "crontab": r"""#!/bin/bash
f=$FAKE_STATE/crontab
[[ $1 == -u && $2 == "$FAKE_OWNER" ]] || exit 2
case $3 in
  -l) [[ -e $f ]] || { echo "no crontab for $2" >&2; exit 1; }; cat "$f" ;;
  -r) rm -f "$f"; echo "crontab remove" >>"$FAKE_STATE/calls" ;;
  -) cat >"$f"; echo "crontab replace" >>"$FAKE_STATE/calls" ;;
  *) cp "$3" "$f"; echo "crontab replace" >>"$FAKE_STATE/calls" ;;
esac
""",
    "mysql": r"""#!/bin/bash
state=$FAKE_STATE; q=""; user=""; prev=""
for a in "$@"; do [[ $prev != -e ]] || q=$a; [[ $prev != -u ]] || user=$a; prev=$a; done
field() { sed -E "s/.*$1 = '([^']*)'.*/\1/" <<<"$q"; }
if [[ -n $user ]]; then
  # A login as a customer account: refused while locked, or for the owner while the domain is disabled.
  if [[ -e $state/locked.$user@localhost ]]; then echo "ERROR 4151 (HY000): Access denied, this account is locked" >&2; exit 1; fi
  if [[ $user == "$FAKE_OWNER" && -e $state/disabled.$FAKE_DOMAIN ]]; then echo "ERROR 1045 (28000): Access denied" >&2; exit 1; fi
  echo "login $user $q" >>"$state/calls"
  if [[ ${FAKE_PROBE_FAILS:-0} == 1 && $q == CREATE* ]]; then exit 1; fi
  echo 1; exit 0
fi
case $q in
  "SELECT DISTINCT User, Host FROM ("*)
    [[ $q != *"FROM ()"* ]] || { echo "ERROR 1064: empty derived table" >&2; exit 1; }
    cat "$state/accounts" ;;
  *account_locked*) if [[ -e $state/locked.$(field User)@$(field Host) ]]; then echo 1; else echo false; fi ;;
  *'$.plugin'*) echo mysql_native_password ;;
  *authentication_string*) echo "*HASH-$(field User)" ;;
  "SHOW GRANTS FOR "*)
    printf "GRANT USAGE ON *.* TO \`u\`@\`h\` IDENTIFIED BY PASSWORD '*AB12'\nGRANT ALL PRIVILEGES ON \`%s\`.* TO \`u\`@\`h\`\n" "$FAKE_DB"
    if [[ ${FAKE_GRANT_SECRET:-0} == 1 ]]; then echo "GRANT PROXY ON x TO y IDENTIFIED BY 'plain'"; fi ;;
  *is_role*) echo "${FAKE_ROLES:-0}" ;;
  *@@event_scheduler*) echo "${FAKE_EVENTS:-0}" ;;
  *"Insert_priv = 'Y' OR"*) echo "${FAKE_GLOBAL_WRITERS:-0}" ;;
  *"Db NOT IN"*) if [[ $(field User) == "${FAKE_SHARED_USER:-}" ]]; then echo 1; else echo 0; fi ;;
  *"Create_priv = 'Y' AND Insert_priv"*) echo "${FAKE_OWNER_CAN_PROBE:-1}" ;;
  "ALTER USER "*)
    u=$(sed -E "s/^ALTER USER '([^']*)'@.*/\1/" <<<"$q"); h=$(sed -E "s/^ALTER USER '[^']*'@'([^']*)'.*/\1/" <<<"$q")
    if [[ $q == *"ACCOUNT LOCK" ]]; then : >"$state/locked.$u@$h"; else rm -f "$state/locked.$u@$h"; fi
    echo "$q" >>"$state/calls" ;;
  "SELECT ID FROM information_schema.processlist"*) for c in "$state"/conn.*; do [[ ! -e $c ]] || echo "${c##*.}"; done ;;
  "SELECT COUNT(*) FROM information_schema.processlist WHERE User = "*) u=$(field User); n=0; for c in "$state"/conn.*; do [[ ! -e $c ]] || [[ $(<"$c") != "$u" ]] || n=$((n + 1)); done; echo $n ;;
  "KILL "*) rm -f "$state/conn.${q#KILL }"; echo "$q" >>"$state/calls" ;;
  *) echo "unexpected query: $q" >&2; exit 9 ;;
esac
""",
    "sshd": '#!/bin/bash\necho "subsystem sftp ${FAKE_SFTP:-/usr/lib/openssh/sftp-server}"\n',
    # The vhost answers the disabled page while it carries the AliasMatch, else the application.
    "curl": r"""#!/bin/bash
host=""; with_status=0; code=200; address=""; port=""
while (($#)); do case $1 in --resolve) host=${2%%:*}; address=${2#*:*:}; port=${2#*:};port=${port%%:*}; shift ;; --write-out) with_status=1; shift ;; esac; shift; done
printf '%s %s\n' "$host" "$address" >>"$FAKE_STATE/probed_bindings"
if [[ ${FAKE_REQUIRE_NATIVE_BINDING:-0} == 1 && $address != "${FAKE_NATIVE_ADDRS:-10.0.0.1}" ]]; then printf '\n000'; exit 0; fi
if [[ ${FAKE_HTTP_REDIRECT:-0} == 1 && $port == 80 ]]; then
  printf 'Native HTTPS redirect'; code=301
elif [[ -n ${FAKE_NEUTRAL_NAME:-} && $host == "$FAKE_NEUTRAL_NAME" ]]; then
  [[ ${FAKE_NEUTRAL_TRANSPORT_FAIL:-0} != 1 ]] || exit 7
  printf '%s' "${FAKE_NEUTRAL_BODY-Not Found}"; code=${FAKE_NEUTRAL_STATUS:-404}
elif grep -q AliasMatch "$PRAHO_APACHE_SITES/$host.conf" 2>/dev/null; then cat "$FAKE_PAGE_DIR/disabled_by_virtualmin.html"; else echo "APP-RAN"; fi
[[ $with_status == 0 ]] || printf '\n%s' "$code"
""",
    "python3": PAIR_SHIMS["python3"],
    "ps": r"""#!/bin/bash
if [[ $* == "-eo args=" ]]; then cat "$FAKE_STATE/ps_args" 2>/dev/null; exit 0; fi
cat "$FAKE_STATE/ps_user" 2>/dev/null; exit 0
""",
    # After the kill php-fpm respawns fresh idle workers; FAKE_SURVIVOR keeps one that started before it.
    "pkill": r"""#!/bin/bash
echo "pkill $*" >>"$FAKE_STATE/calls"
printf '0 php-fpm8.2\n0 fcgiwrap\n' >"$FAKE_STATE/ps_user"
if [[ ${FAKE_SURVIVOR:-0} == 1 ]]; then echo "999999 php-fpm8.2" >>"$FAKE_STATE/ps_user"; fi
""",
}

_SDBM = """use Fcntl; use SDBM_File; my ($db, $mode, @kv) = @ARGV;
tie(my %s, "SDBM_File", $db, $mode eq "w" ? O_RDWR|O_CREAT : O_RDONLY, 0600) or die "tie";
if ($mode eq "w") { while (@kv) { my $k = shift @kv; $s{$k} = shift @kv } }
else { print join("\\n", map { "$_=$s{$_}" } sort keys %s), "\\n" }"""


def _lines(rows: list[tuple[str, ...]]) -> str:
    return base64.b64encode("".join("\t".join(row) + "\n" for row in rows).encode()).decode()


class BarrierScriptCase(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self.bin, self.state, self.run_dir, self.state_dir, self.webmin, self.proc, self.sites, self.page = (
            root / name for name in ("bin", "state", "run", "keep", "webmin", "proc", "sites", "page")
        )
        for directory in (self.bin, self.state, self.webmin, self.proc, self.sites, self.page):
            directory.mkdir()
        self.bin.chmod(0o700)
        for name, body in {**CHAIN_SHIMS, **_SHIMS}.items():
            shim = self.bin / name
            shim.write_text(body)
            shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        (self.page / "disabled_by_virtualmin.html").write_text("<html>This website is disabled</html>\n")
        for name in (DOMAIN, CHILD):
            (self.sites / f"{name}.conf").write_text(
                f"<VirtualHost 10.0.0.1:80>\n    ServerName {name}\n</VirtualHost>\n"
                f"<VirtualHost 10.0.0.1:443>\n    ServerName {name}\n</VirtualHost>\n"
            )
        (self.state / "crontab").write_text(CRONTAB)
        self.accounts = [(OWNER, "localhost"), (OWNER, "127.0.0.1"), (EXTRA, "localhost")]
        self._write_accounts()
        (self.state / "conn.41").write_text(EXTRA)  # An open connection of the extra account
        (self.state / "ps_user").write_text("5000 php-fpm8.2\n4000 perl\n")
        self._sessions({"s-owner": f"{OWNER} 1792000000 10.1.1.1", "s-staff": "staff 1792000000 10.1.1.2"})
        self.webmin_process = subprocess.Popen(["/bin/sleep", "60"])  # Stands in for miniserv
        self.addCleanup(self._stop_webmin)
        (self.webmin / "miniserv.pid").write_text(str(self.webmin_process.pid))
        self.neutral_helper = self.bin / "neutral-helper.py"
        self.neutral_helper.write_text(
            "# Root-owned helper boundary; python3 shim implements its read-only contract.\n"
        )
        self.neutral_helper.chmod(0o700)
        self.binding_helper = self.bin / "apache-bindings.py"
        self.binding_helper.write_text("# Root-private fixed read-only Apache binding query fixture\n")
        self.binding_helper.chmod(0o700)

    def _stop_webmin(self) -> None:
        if self.webmin_process.poll() is None:
            self.webmin_process.kill()
        self.webmin_process.wait()

    def _write_accounts(self) -> None:
        (self.state / "accounts").write_text("".join(f"{user}\t{host}\n" for user, host in self.accounts))

    def _sessions(self, entries: dict[str, str] | None = None) -> dict[str, str]:
        """Write entries into Webmin's session store, or read it."""
        args = [str(self.webmin / "sessiondb"), "w" if entries is not None else "r"]
        for key, value in (entries or {}).items():
            args += [key, value]
        out = subprocess.run(["/usr/bin/perl", "-e", _SDBM, *args], capture_output=True, text=True, check=True)  # noqa: S603  # Fixed argv
        return dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)

    def run_script(self, action: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "PRAHO_BARRIER_ACTION": action,
            "PRAHO_DOMAIN": DOMAIN,
            "PRAHO_DOMAIN_ID": DOMAIN_ID,
            "PRAHO_OPERATION_TOKEN": TOKEN,
            "PRAHO_LOCK_WAIT": "1",
            "PRAHO_DRAIN_WAIT": "1",
            "PRAHO_RUN_DIR": str(self.run_dir),
            "PRAHO_STATE_DIR": str(self.state_dir),
            "PRAHO_WEBMIN_VAR": str(self.webmin),
            "PRAHO_PROC_DIR": str(self.proc),
            "PRAHO_APACHE_SITES": str(self.sites),
            "PRAHO_NEUTRAL_HELPER": str(self.neutral_helper),
            "PRAHO_APACHE_BINDINGS_HELPER": str(self.binding_helper),
            "FAKE_NATIVE_ADDRS": "10.0.0.1",
            "FAKE_STATE": str(self.state),
            "FAKE_DOMAIN": DOMAIN,
            "FAKE_DOMAIN_ID": DOMAIN_ID,
            "FAKE_CHILD": CHILD,
            "FAKE_OWNER": OWNER,
            "FAKE_DB": DB,
            "FAKE_DB_USERS": EXTRA,
            "FAKE_PAGE_DIR": str(self.page),
            **overrides,
        }
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False)  # noqa: S603  # Fixed argv

    def step(self, action: str, **overrides: str) -> dict[str, Any]:
        completed = self.run_script(action, **overrides)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = [line for line in completed.stdout.splitlines() if line.startswith("BARRIER_RESULT=")]
        self.assertEqual(len(lines), 1, completed.stdout)
        payload: dict[str, Any] = json.loads(base64.b64decode(lines[0].removeprefix("BARRIER_RESULT=")))
        self.assertEqual((payload["action"], payload["token"], payload["domain_id"]), (action, TOKEN, DOMAIN_ID))
        return payload

    def calls(self) -> list[str]:
        path = self.state / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def record(self, **overrides: str) -> dict[str, Any]:
        recorded = self.step("record", **overrides)
        self.assertEqual(recorded["outcome"], "ok", recorded)
        return recorded

    def inputs(self, recorded: dict[str, Any]) -> dict[str, str]:
        """What PRAHO passes back to apply, verify and release from the persisted record."""
        return {
            "PRAHO_ACCOUNTS": _lines(
                [(a["user"], a["host"], "1" if a["locked"] else "0") for a in recorded["accounts"]]
            ),
            "PRAHO_ENABLED": _lines([(e["name"], "1" if e["enabled"] else "0") for e in recorded["enabled"]]),
            "PRAHO_HAS_CRONTAB": "1" if recorded["has_crontab"] else "0",
            "PRAHO_CRONTAB_ACTIVE_SHA": recorded["active_sha"],
        }

    def apply(self, recorded: dict[str, Any], **overrides: str) -> dict[str, Any]:
        return self.step("apply", **{**self.inputs(recorded), **overrides})

    def _suspend(self, name: str) -> None:
        """Leave `name` as Virtualmin's disable does: marked, each vhost on the disabled page, jobs commented."""
        (self.state / f"disabled.{name}").touch()
        conf = self.sites / f"{name}.conf"
        alias = f"    AliasMatch ^/.*$ {self.page}/disabled_by_virtualmin.html\n"
        conf.write_text(conf.read_text() + alias * 2)
        if name == DOMAIN:
            (self.state / "crontab").write_text(
                "".join(
                    f"# {line} # VIRTUALMIN DISABLE\n" if line and not line.startswith("#") else f"{line}\n"
                    for line in CRONTAB.splitlines()
                )
            )

    def locked(self) -> set[str]:
        return {path.name.removeprefix("locked.") for path in self.state.glob("locked.*")}

    def disabled(self) -> set[str]:
        return {path.name.removeprefix("disabled.") for path in self.state.glob("disabled.*")}


class RecordTests(BarrierScriptCase):
    def test_existing_native_https_redirect_does_not_invalidate_the_tls_disabled_page_proof(self) -> None:
        recorded = self.record()
        applied = self.apply(recorded, FAKE_HTTP_REDIRECT="1")
        self.assertEqual(applied["outcome"], "ok", applied)

    def test_http_only_native_account_uses_its_actual_http_binding_without_a_tls_fallback(self) -> None:
        recorded = self.record()
        applied = self.apply(recorded, FAKE_NATIVE_PORTS="80", FAKE_REQUIRE_NATIVE_BINDING="1")
        self.assertEqual(applied["outcome"], "ok", applied)

    def test_explicit_native_bindings_are_verified_instead_of_unrelated_loopback_default(self) -> None:
        recorded = self.record()
        applied = self.apply(recorded, FAKE_REQUIRE_NATIVE_BINDING="1")
        self.assertEqual(applied["outcome"], "ok", applied)
        probes = (self.state / "probed_bindings").read_text().splitlines()
        self.assertTrue(probes)
        self.assertTrue(all(line.endswith(" 10.0.0.1") for line in probes))

    def test_a_web_only_account_can_record_apply_verify_and_release_without_database_queries(self) -> None:
        recorded = self.record(FAKE_DB="")

        self.assertEqual(recorded["databases"], [])
        self.assertEqual(recorded["accounts"], [])
        applied = self.apply(recorded, FAKE_DB="")
        self.assertEqual(applied["outcome"], "ok", applied)
        held = self.step("verify", **self.inputs(recorded), FAKE_DB="", PRAHO_KILLED_AT=str(applied["killed_at"]))
        self.assertEqual(held["outcome"], "ok", held)
        released = self.step("release", **self.inputs(recorded), FAKE_DB="")
        self.assertEqual(released["outcome"], "ok", released)
        self.assertFalse([call for call in self.calls() if call.startswith("ALTER USER ")])
        self.assertEqual((self.state / "crontab").read_text(), CRONTAB)

    def test_the_record_lists_what_a_release_needs_and_keeps_the_crontab_on_the_node(self) -> None:
        recorded = self.record()

        self.assertEqual(recorded["enabled"], [{"name": DOMAIN, "enabled": True}, {"name": CHILD, "enabled": True}])
        self.assertEqual(recorded["databases"], [DB])
        self.assertEqual(
            sorted((a["user"], a["host"], a["locked"]) for a in recorded["accounts"]),
            sorted((user, host, False) for user, host in self.accounts),
        )
        self.assertTrue(recorded["has_crontab"])
        self.assertNotIn("report", json.dumps(recorded), "the crontab never leaves the node")
        kept = self.state_dir / f"migration-{DOMAIN_ID}.{TOKEN}.crontab"
        self.assertEqual(kept.read_text(), CRONTAB)
        self.assertEqual(stat.S_IMODE(kept.stat().st_mode), 0o600)
        self.assertEqual(self.calls(), [], "a record changes nothing on the node")

    def test_a_replay_after_the_fence_keeps_the_first_copy(self) -> None:
        first = self.record()
        (self.state / "crontab").write_text("# 0 3 * * * /home/shop/bin/report # VIRTUALMIN DISABLE\n")

        second = self.record()

        self.assertEqual(second["active_sha"], first["active_sha"])

    def test_every_reason_the_barrier_cannot_hold_refuses_before_anything_is_touched(self) -> None:
        cases = {
            "mail_feature": {"FAKE_MAIL_ON": CHILD},
            "internal_sftp": {"FAKE_SFTP": "internal-sftp"},
            "database_roles": {"FAKE_ROLES": "1"},
            "database_events": {"FAKE_EVENTS": "1"},
            "database_global_writer": {"FAKE_GLOBAL_WRITERS": "1"},
            "shared_account": {"FAKE_SHARED_USER": EXTRA},
            "unmanaged_account": {"FAKE_DB_USERS": ""},
            "owner_cannot_probe": {"FAKE_OWNER_CAN_PROBE": "0"},
            "accounts_unreadable": {"FAKE_GRANT_SECRET": "1"},
        }
        for reason, overrides in cases.items():
            with self.subTest(reason=reason):
                refused = self.step("record", **overrides)
                self.assertEqual((refused["outcome"], refused["reason"]), ("refused", reason))
        self.assertEqual(self.calls(), [])

    def test_an_enabled_domain_whose_owner_account_is_locked_is_refused(self) -> None:
        (self.state / f"locked.{OWNER}@localhost").touch()

        refused = self.step("record")

        self.assertEqual((refused["outcome"], refused["reason"]), ("refused", "owner_account_locked"))


class ApplyTests(BarrierScriptCase):
    def test_native_feature_listing_trailer_cannot_hide_mail_and_admit_an_unfenced_mail_account(self) -> None:
        result = self.step("record", FAKE_MAIL_ON=CHILD, FAKE_DELAY_FEATURE_TRAILER="1")
        self.assertEqual((result["outcome"], result["reason"]), ("refused", "mail_feature"))

    def test_root_neutral_child_page_proof_keeps_all_native_disabled_and_writer_fences(self) -> None:
        recorded = self.record()
        options = {"FAKE_NEUTRAL_NAME": CHILD, "FAKE_NEUTRAL_PROOF": "ready"}
        applied = self.apply(recorded, **options)
        self.assertEqual((applied["outcome"], applied["reason"]), ("ok", "applied"))
        self.assertEqual(self.disabled(), {DOMAIN, CHILD})
        self.assertEqual(self.locked(), {f"{user}@{host}" for user, host in self.accounts})
        proof = (self.state / "neutral_calls").read_text()
        self.assertIn(f"--name {CHILD} --owner {OWNER} --parent {DOMAIN} --parent-id {DOMAIN_ID} --host {CHILD}", proof)
        self.assertEqual(self.step("verify", **self.inputs(recorded), **options)["outcome"], "ok")
        (self.state / f"locked.{EXTRA}@localhost").unlink()
        failed = self.step("verify", **self.inputs(recorded), **options)
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"account_open:{EXTRA}@localhost"))

    def test_source_neutral_exception_refuses_unowned_proofs_and_tenant_404_mimics(self) -> None:
        recorded = self.record()
        for proof in ("missing", "malformed_state", "foreign_id", "mutable_guard", "tenant_404"):
            with self.subTest(proof=proof):
                failed = self.apply(recorded, FAKE_NEUTRAL_NAME=CHILD, FAKE_NEUTRAL_PROOF=proof)
                self.assertEqual(
                    (failed["outcome"], failed["reason"]), ("failed", f"barrier_not_verified:serving:{CHILD}")
                )
        failed = self.apply(
            recorded, FAKE_NEUTRAL_NAME=CHILD, FAKE_NEUTRAL_PROOF="ready", FAKE_NEUTRAL_BODY="tenant content"
        )
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"barrier_not_verified:serving:{CHILD}"))

    def test_primary_customer_page_is_never_a_neutral_guard_exception(self) -> None:
        failed = self.apply(self.record(), FAKE_NEUTRAL_NAME=DOMAIN, FAKE_NEUTRAL_PROOF="ready")
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"barrier_not_verified:serving:{DOMAIN}"))
        self.assertFalse((self.state / "neutral_calls").exists())

    def test_denied_neutral_proof_cannot_fall_back_to_a_matching_tenant_page_on_404_or_transport_failure(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")
        for body, status, transport in (("Not Found", "404", "0"), ("", "000", "0"), ("", "200", "1")):
            with self.subTest(body=body, status=status, transport=transport):
                (self.page / "disabled_by_virtualmin.html").write_text(body)
                failed = self.step(
                    "verify",
                    **self.inputs(recorded),
                    FAKE_NEUTRAL_NAME=CHILD,
                    FAKE_NEUTRAL_PROOF="foreign_id",
                    FAKE_NEUTRAL_BODY=body,
                    FAKE_NEUTRAL_STATUS=status,
                    FAKE_NEUTRAL_TRANSPORT_FAIL=transport,
                )
                self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"serving:{CHILD}"))

    def test_source_neutral_helper_cannot_be_mutable_or_replace_native_child_disabled_state(self) -> None:
        recorded = self.record()
        self.neutral_helper.chmod(0o777)
        failed = self.apply(recorded, FAKE_NEUTRAL_NAME=CHILD, FAKE_NEUTRAL_PROOF="ready")
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"barrier_not_verified:serving:{CHILD}"))
        self.neutral_helper.chmod(0o700)
        original = self.neutral_helper.with_suffix(".saved")
        self.neutral_helper.rename(original)
        self.neutral_helper.symlink_to(original)
        failed = self.step("verify", **self.inputs(recorded), FAKE_NEUTRAL_NAME=CHILD, FAKE_NEUTRAL_PROOF="ready")
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"serving:{CHILD}"))
        self.neutral_helper.unlink()
        original.rename(self.neutral_helper)
        (self.state / f"disabled.{CHILD}").unlink()
        failed = self.step("verify", **self.inputs(recorded), FAKE_NEUTRAL_NAME=CHILD, FAKE_NEUTRAL_PROOF="ready")
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", f"not_disabled:{CHILD}"))

    def test_the_fence_closes_every_write_path_and_the_barrier_holds(self) -> None:
        recorded = self.record()

        applied = self.apply(recorded)

        self.assertEqual((applied["outcome"], applied["reason"]), ("ok", "applied"), applied)
        self.assertEqual(self.disabled(), {DOMAIN, CHILD})
        self.assertEqual(self.locked(), {f"{user}@{host}" for user, host in self.accounts})
        self.assertFalse(list(self.state.glob("conn.*")), "the open connection was killed")
        self.assertEqual(self._sessions(), {"s-staff": "staff 1792000000 10.1.1.2"}, "only the owner's session goes")
        self.assertEqual(self.webmin_process.wait(timeout=5), -signal.SIGHUP, "Webmin was reloaded")
        self.assertNotIn("/home/shop/bin/report\n", (self.state / "crontab").read_text().replace("# ", "#"))

    def test_the_fence_on_administration_comes_before_the_accounts_are_counted_and_locked(self) -> None:
        recorded = self.record()

        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        calls = self.calls()
        disable = next(i for i, call in enumerate(calls) if call.startswith("disable "))
        kill = next(i for i, call in enumerate(calls) if call.startswith("pkill "))
        locks = [i for i, call in enumerate(calls) if call.endswith("ACCOUNT LOCK")]
        self.assertTrue(locks)
        self.assertLess(max(disable, kill), min(locks))

    def test_an_account_that_appears_under_the_fence_fails_the_barrier(self) -> None:
        recorded = self.record()
        self.accounts.append(("intruder", "localhost"))
        self._write_accounts()

        applied = self.apply(recorded)

        self.assertEqual((applied["outcome"], applied["reason"]), ("failed", "accounts_changed"))
        self.assertEqual(self.locked(), set(), "nothing is locked from a stale inventory")

    def test_a_webmin_request_still_running_stops_the_fence_before_the_domain_is_touched(self) -> None:
        recorded = self.record()
        request = self.proc / "4242"
        request.mkdir()
        (request / "environ").write_bytes(f"PATH=/usr/bin\0REMOTE_USER={OWNER}\0".encode())

        applied = self.apply(recorded)

        self.assertEqual((applied["outcome"], applied["reason"]), ("failed", "webmin_request_running"))
        self.assertFalse([call for call in self.calls() if call.startswith("disable ")])

    def test_a_cancelled_operation_never_starts(self) -> None:
        recorded = self.record()
        (self.run_dir / f"migration-{DOMAIN_ID}.cancelled.{TOKEN}").touch()

        applied = self.apply(recorded)

        self.assertEqual((applied["outcome"], applied["reason"]), ("refused", "cancelled"))
        self.assertEqual(self.calls(), [])

    def test_a_held_lock_is_busy_not_a_failure(self) -> None:
        recorded = self.record()

        applied = self.apply(recorded, FAKE_LOCK_HELD="1")

        self.assertEqual((applied["outcome"], applied["reason"]), ("busy", "lock_busy"))
        self.assertEqual(self.calls(), [])


class VerifyTests(BarrierScriptCase):
    def setUp(self) -> None:
        super().setUp()
        self.recorded = self.record()
        applied = self.apply(self.recorded)
        self.assertEqual(applied["outcome"], "ok", applied)
        self.killed_at = str(applied["killed_at"])

    def verify(self, **overrides: str) -> dict[str, Any]:
        return self.step("verify", **{**self.inputs(self.recorded), "PRAHO_KILLED_AT": self.killed_at, **overrides})

    def test_a_barrier_that_holds_verifies(self) -> None:
        self.assertEqual(self.verify()["outcome"], "ok")

    def test_every_open_write_path_breaks_the_barrier(self) -> None:  # noqa: C901  # One table of breaches, each undone
        def reopen_job() -> None:
            (self.state / "crontab").write_text("0 3 * * * /home/shop/bin/report\n")

        def enable_child() -> None:
            (self.state / f"disabled.{CHILD}").unlink()

        def serve_the_child() -> None:
            conf = self.sites / f"{CHILD}.conf"
            conf.write_text("\n".join(line for line in conf.read_text().splitlines() if "AliasMatch" not in line))

        def unlock_extra() -> None:
            (self.state / f"locked.{EXTRA}@localhost").unlink()

        def reconnect_extra() -> None:
            (self.state / "conn.77").write_text(EXTRA)

        def new_account() -> None:
            self.accounts.append(("intruder", "localhost"))
            self._write_accounts()

        def new_session() -> None:
            self._sessions({"s-again": f"{OWNER} 1792000100 10.1.1.1"})

        def old_process() -> None:
            (self.state / "ps_user").write_text("999999 php-fpm8.2\n")

        def other_process() -> None:
            (self.state / "ps_user").write_text("0 perl\n")

        breaks = {
            "cron_job_active": reopen_job,
            f"not_disabled:{CHILD}": enable_child,
            f"vhost_open:{CHILD}": serve_the_child,
            f"account_open:{EXTRA}@localhost": unlock_extra,
            f"account_connected:{EXTRA}": reconnect_extra,
            "accounts_changed": new_account,
            "webmin_session": new_session,
            "user_process_survived:php-fpm8.2": old_process,
            "user_process:perl": other_process,
        }
        for reason, breach in breaks.items():
            with self.subTest(reason=reason):
                saved = {path: path.read_bytes() for path in (*self.state.iterdir(), *self.sites.iterdir())}
                sessions = self._sessions()
                accounts = list(self.accounts)
                breach()
                broken = self.verify()
                self.assertEqual((broken["outcome"], broken["reason"]), ("failed", reason))
                for path in (*self.state.iterdir(), *self.sites.iterdir()):
                    if path not in saved:
                        path.unlink()
                for path, content in saved.items():
                    path.write_bytes(content)
                for key in set(self._sessions()) - set(sessions):
                    subprocess.run(  # noqa: S603  # Fixed argv
                        [
                            "/usr/bin/perl",
                            "-e",
                            'use Fcntl; use SDBM_File; tie(my %s,"SDBM_File",$ARGV[0],O_RDWR,0600) or die; delete $s{$ARGV[1]}',
                            str(self.webmin / "sessiondb"),
                            key,
                        ],
                        check=True,
                    )
                self.accounts = accounts
                self.assertEqual(self.verify()["outcome"], "ok", "the breach was undone")

    def test_a_vhost_answering_the_application_breaks_the_barrier(self) -> None:
        conf = self.sites / f"{DOMAIN}.conf"
        conf.write_text(conf.read_text().replace("AliasMatch", "# AliasMatch", 1))

        broken = self.verify()

        self.assertEqual((broken["outcome"], broken["reason"]), ("failed", f"vhost_open:{DOMAIN}"))


class ReleaseTests(BarrierScriptCase):
    def release(self, recorded: dict[str, Any], **overrides: str) -> dict[str, Any]:
        return self.step("release", **{**self.inputs(recorded), **overrides})

    def test_a_release_restores_exactly_what_was_recorded_and_proves_a_write(self) -> None:
        (self.state / f"locked.{EXTRA}@localhost").touch()  # Locked before the migration: stays locked
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        released = self.release(recorded)

        self.assertEqual((released["outcome"], released["reason"]), ("ok", "released"), released)
        self.assertEqual(self.disabled(), set())
        self.assertEqual(self.locked(), {f"{EXTRA}@localhost"})
        self.assertEqual((self.state / "crontab").read_text(), CRONTAB)
        self.assertTrue(
            [call for call in self.calls() if call.startswith(f"login {OWNER} CREATE TABLE praho_barrier_probe_")]
        )
        self.assertFalse((self.state_dir / f"migration-{DOMAIN_ID}.{TOKEN}.crontab").exists(), "the kept copy goes")

    def test_a_release_under_a_new_operation_token_uses_the_recorded_copy(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")
        new_token = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

        completed = self.run_script(
            "release",
            **{
                **self.inputs(recorded),
                "PRAHO_OPERATION_TOKEN": new_token,
                "PRAHO_SAVED_TOKEN": TOKEN,
                "PRAHO_PREVIOUS_TOKEN": TOKEN,
                "FAKE_ENABLE_STRANDS_CRON": "1",
            },
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = [line for line in completed.stdout.splitlines() if line.startswith("BARRIER_RESULT=")]
        self.assertEqual(len(lines), 1, completed.stdout)
        payload = json.loads(base64.b64decode(lines[0].removeprefix("BARRIER_RESULT=")))
        self.assertEqual((payload["outcome"], payload["reason"], payload["token"]), ("ok", "released", new_token))
        self.assertEqual((self.state / "crontab").read_text(), CRONTAB)
        self.assertFalse((self.state_dir / f"migration-{DOMAIN_ID}.{TOKEN}.crontab").exists())

    def test_jobs_stranded_by_a_failed_enable_are_put_back_from_the_kept_copy(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        released = self.release(recorded, FAKE_ENABLE_STRANDS_CRON="1")

        self.assertEqual(released["outcome"], "ok", released)
        self.assertIn("crontab replace", self.calls())
        self.assertEqual((self.state / "crontab").read_text(), CRONTAB)

    def test_a_suspended_domain_stays_suspended_and_its_owner_refused(self) -> None:
        for name in (DOMAIN, CHILD):
            self._suspend(name)
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        released = self.release(recorded)

        self.assertEqual(released["outcome"], "ok", released)
        self.assertEqual(self.disabled(), {DOMAIN, CHILD})
        self.assertFalse([call for call in self.calls() if call.startswith("enable ")])
        self.assertFalse([call for call in self.calls() if call.startswith("login ")], "no probe write while suspended")

    def test_a_child_recorded_disabled_is_not_enabled_with_its_parent(self) -> None:
        self._suspend(CHILD)
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        self.assertEqual(self.release(recorded)["outcome"], "ok")

        self.assertEqual(self.disabled(), {CHILD})

    def test_a_probe_write_that_fails_fails_the_release(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")

        released = self.release(recorded, FAKE_PROBE_FAILS="1")

        self.assertEqual((released["outcome"], released["reason"]), ("failed", "probe_write_failed"))
        self.assertTrue((self.state_dir / f"migration-{DOMAIN_ID}.{TOKEN}.crontab").exists(), "kept until verified")

    def test_a_release_cancels_the_previous_attempt_before_waiting_for_the_lock(self) -> None:
        recorded = self.record()

        released = self.release(recorded, PRAHO_PREVIOUS_TOKEN=PREVIOUS, FAKE_LOCK_HELD="1")

        self.assertEqual(released["outcome"], "busy")
        self.assertTrue((self.run_dir / f"migration-{DOMAIN_ID}.cancelled.{PREVIOUS}").exists())
        self.assertTrue((self.state_dir / f"migration-{DOMAIN_ID}.cancelled.{PREVIOUS}").exists())

    def test_completed_release_replay_preserves_customer_changes_and_blocks_old_apply_after_reboot(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")
        self.assertEqual(self.release(recorded)["outcome"], "ok")
        changed = "MAILTO=changed@example.com\n0 8 * * * /home/shop/new-job\n"
        (self.state / "crontab").write_text(changed)
        (self.state / f"locked.{OWNER}@localhost").touch()
        calls = self.calls()
        for path in self.run_dir.iterdir():
            path.unlink()
        replay = self.release(recorded)
        self.assertEqual((replay["outcome"], replay["reason"]), ("ok", "released"))
        self.assertEqual((self.state / "crontab").read_text(), changed)
        self.assertTrue((self.state / f"locked.{OWNER}@localhost").exists())
        self.assertEqual(self.calls(), calls)
        applied = self.apply(recorded)
        self.assertEqual((applied["outcome"], applied["reason"]), ("refused", "cancelled"))
        self.assertEqual(self.calls(), calls)

    def test_an_interrupted_release_never_reapplies_its_original_record(self) -> None:
        recorded = self.record()
        self.assertEqual(self.apply(recorded)["outcome"], "ok")
        self.assertEqual(self.release(recorded, FAKE_PROBE_FAILS="1")["reason"], "probe_write_failed")
        changed = "0 8 * * * /home/shop/new-job\n"
        (self.state / "crontab").write_text(changed)
        calls = self.calls()
        replay = self.release(recorded)
        self.assertEqual((replay["outcome"], replay["reason"]), ("failed", "release_interrupted"))
        self.assertEqual((self.state / "crontab").read_text(), changed)
        self.assertEqual(self.calls(), calls)


class IdleTests(BarrierScriptCase):
    def test_native_http_children_without_domain_arguments_and_their_cgi_parent_keep_it_busy(self) -> None:
        for arguments in (
            "/usr/share/webmin/virtual-server/delete-domain.pl\n",
            "/usr/share/webmin/virtual-server/restore-domain.pl\n",
            "/usr/share/webmin/virtual-server/remote.cgi\n",
        ):
            with self.subTest(arguments=arguments):
                (self.state / "ps_args").write_text(arguments)
                busy = self.step("idle")
                self.assertEqual((busy["outcome"], busy["reason"]), ("busy", "operation_running"))

    def test_creation_and_deletion_of_the_domain_also_keep_it_busy(self) -> None:
        for program in ("create", "delete"):
            with self.subTest(program=program):
                (self.state / "ps_args").write_text(
                    f"/usr/bin/perl /usr/share/webmin/virtual-server/{program}-domain.pl --domain {DOMAIN}\n"
                )
                busy = self.step("idle")
                self.assertEqual((busy["outcome"], busy["reason"]), ("busy", "operation_running"))

    def test_a_restore_of_the_domain_running_on_the_node_keeps_it_busy(self) -> None:
        (self.state / "ps_args").write_text(
            f"/usr/bin/perl /usr/share/webmin/virtual-server/restore-domain.pl --domain {DOMAIN} --source /x\n"
        )

        busy = self.step("idle")

        self.assertEqual((busy["outcome"], busy["reason"]), ("busy", "operation_running"))

    def test_another_domains_backup_does_not(self) -> None:
        (self.state / "ps_args").write_text(
            "/usr/bin/perl /usr/share/webmin/virtual-server/backup-domain.pl --domain other.example.com --dest /y\n"
        )

        self.assertEqual(self.step("idle")["outcome"], "ok")
