"""Exercise the real Perl adapter against the native Virtualmin API boundary."""

import fcntl
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

SOURCE = Path(__file__).resolve().parents[2] / "infrastructure/ansible/playbooks/files/praho-usage-metadata.pl"
HOOK = SOURCE.with_name("praho-usage-hook")
INSTALLATION = "12345678-1234-1234-1234-123456789abc"

# The adapter's production bootstrap is retained; only root identity and native
# filesystem locations are substituted. The native library is the external
# boundary. None of the adapter's reconciliation/measurement logic is mocked.
NATIVE = r'''
use JSON::PP ();
use Text::ParseWords ();
our (%config, $module_config_directory, $module_config_file, $templates_dir, @list_templates_cache);
our ($fixture, $fixture_root);
$fixture_root = $ENV{'PRAHO_NATIVE_FIXTURE'};
open(my $input, '<', "$fixture_root/fixture.json") or die;
local $/; $fixture = JSON::PP::decode_json(<$input>); close $input;
$module_config_directory = "$fixture_root/native";
$module_config_file = "$module_config_directory/config";
$templates_dir = "$module_config_directory/templates";
read_file($module_config_file, \%config) or die;
sub list_domains { return @{$fixture->{'domains'}}; }
sub get_domain { my ($id) = @_; return (grep { $_->{'id'} eq $id } list_domains())[0]; }
sub list_templates {
    unless (@list_templates_cache) {
        for my $t (@{$fixture->{'templates'}}) {
            my $saved = read_file_contents("$templates_dir/$t->{'id'}");
            $t = JSON::PP::decode_json($saved) if defined $saved;
            $t->{'web'} = $config{'apache_config'} if $t->{'id'} == 0;
            push @list_templates_cache, $t;
        }
    }
    return @list_templates_cache;
}
sub require_apache {}
sub obtain_lock_web {
    list_templates();
    if ($fixture->{'mutate_inheritance'}) {
        for my $t (@list_templates_cache) { $t->{'web'} = $config{'apache_config'} if !$t->{'web'}; }
    }
}
sub release_lock_web {}
sub get_apache_virtual {
    my ($name, $port) = @_;
    my ($d) = grep { $_->{'dom'} eq $name } list_domains();
    $d = get_domain($d->{'alias'}) if $d->{'alias'};
    my $file = "$module_config_directory/$d->{'id'}-$port.conf";
    return () unless -f $file;
    open(my $f, '<', $file) or die;
    local $/; my $members = JSON::PP::decode_json(<$f>); close $f;
    $members->{'file'} = $file;
    my $v = {file => $file, line => 0, members => $members};
    return ($v, $members, [$v]);
}
sub read_file_contents { open(my $f, '<', $_[0]) or return undef; local $/; return <$f>; }
sub write_file_contents { open(my $f, '>', $_[0]) or die; print $f $_[1]; close $f or die; }
sub flush_file_lines {}
sub lock_file {}
sub unlock_file {}
sub save_template {
    my ($t) = @_;
    write_file_contents("$module_config_directory/domain-template", 'rewritten') if $t->{'id'} <= 1;
    write_file_contents("$templates_dir/$t->{'id'}", JSON::PP->new->canonical->encode($t));
    if ($t->{'id'} == 0) { $config{'apache_config'} = $t->{'web'}; save_module_config(\%config); }
}
sub read_file {
    my ($path, $hash) = @_;
    my $text = read_file_contents($path);
    %$hash = %{JSON::PP::decode_json($text)} if defined $text;
    return defined $text;
}
sub save_module_config { write_file_contents($module_config_file, JSON::PP->new->canonical->encode($_[0])); }
sub write_file { write_file_contents($_[0], JSON::PP->new->canonical->encode($_[1])); }
sub restart_apache {
    open(my $calls, '>>', "$fixture_root/reloads") or die;
    print $calls "reload\n"; close $calls;
    write_file_contents("$fixture_root/state/reconciliation-pending", 'concurrent') if $fixture->{'event_during_reload'};
    return !$fixture->{'fail_reload'};
}
sub domain_databases { return @{$_[0]->{'databases'} || []}; }
sub get_mysql_database_dir { return "$fixture_root/database"; }
sub mysql_size { return (4096); }
package apache;
sub wsplit { return [Text::ParseWords::shellwords($_[0])]; }
sub find_directive {
    my ($key, $members) = @_;
    my @values = $key eq 'CustomLog' ? @{$members->{'logs'}} : ($members->{'name'});
    return wantarray ? @values : $values[-1];
}
sub save_directive {
    my ($key, $values, $members) = @_;
    $members->{'logs'} = $values;
    virtual_server::write_file_contents($members->{'file'}, JSON::PP->new->canonical->encode($members));
}
sub test_config { return $virtual_server::fixture->{'fail_config'} ? 'rejected' : undef; }
1;
'''


class UsagePerlAdapterTests(SimpleTestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.directory)
        self.native = self.root / "native"
        (self.native / "templates").mkdir(parents=True)
        (self.root / "state").mkdir()
        (self.root / "state/installation").write_text(INSTALLATION)
        (self.root / "home/child").mkdir(parents=True)
        (self.root / "database").mkdir()
        self.fixture = {
            "domains": [{"id": "42", "dom": "account.test", "user": "account", "home": str(self.root / "home"), "web": 1}],
            "templates": [{"id": 0, "web": "ServerName ${DOM}\tCustomLog /ordinary.log combined"}],
        }
        self.source = SOURCE.read_text()
        self.source = self.source.replace('unless $> == 0', 'unless 1')
        self.source = self.source.replace('/usr/share/webmin/virtual-server', str(self.native))
        self.source = self.source.replace('/var/lib/praho/usage', str(self.root / "state"))
        self.source = self.source.replace('/var/log/praho', str(self.root / "logs"))
        (self.native / "virtual-server-lib.pl").write_text(NATIVE)
        (self.root / "adapter.pl").write_text(self.source)

    def vhost(self, identity="42", name="account.test", port=80):
        path = self.native / f"{identity}-{port}.conf"
        if not path.exists():
            path.write_text(json.dumps({"name": name, "logs": ["/ordinary.log combined"]}))
        return path

    def run_adapter(self, *, reconcile=True, mode=None):
        (self.root / "fixture.json").write_text(json.dumps(self.fixture))
        config = self.native / "config"
        if not config.exists():
            config.write_text(json.dumps({"post_command": "operator-hook", "apache_config": self.fixture["templates"][0]["web"]}))
        return subprocess.run(  # noqa: S603 -- fixed interpreter and adapter created in this test's private directory
            ["/usr/bin/perl", str(self.root / "adapter.pl"), *([mode or "reconcile"] if reconcile else [])],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "PRAHO_NATIVE_FIXTURE": str(self.root)}, check=False,
        )

    def test_alias_cannot_replace_primary_literal_identity(self):
        path = self.vhost()
        self.fixture["domains"].append({"id": "99", "dom": "alias.test", "alias": "42", "web": 1})
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        logs = json.loads(path.read_text())["logs"]
        self.assertIn(f"v1 {INSTALLATION} 42 ", logs[0])
        self.assertEqual(logs[-1], "/ordinary.log combined")

    def test_child_literal_identity_is_top_level_at_request_time(self):
        self.vhost()
        child = self.vhost("43", "child.test")
        self.fixture["domains"].append({"id": "43", "dom": "child.test", "parent": "42", "home": str(self.root / "home/child"), "web": 1})
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"v1 {INSTALLATION} 42 ", json.loads(child.read_text())["logs"][0])

    def test_inherited_template_is_not_frozen_by_native_vhost_lookup(self):
        self.vhost()
        self.fixture["templates"].append({"id": 7, "web": "", "for_parent": 1})
        self.fixture["mutate_inheritance"] = True
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.native / "templates/7").exists())

    def test_config_failure_restores_native_config_and_template_absence(self):
        path = self.vhost()
        original = path.read_text()
        self.fixture["fail_config"] = True
        result = self.run_adapter()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), original)
        self.assertEqual(json.loads((self.native / "config").read_text())["apache_config"], self.fixture["templates"][0]["web"])
        self.assertFalse((self.native / "templates/0").exists())

    def test_external_child_home_is_unavailable_instead_of_omitted(self):
        self.vhost()
        (self.root / "elsewhere").mkdir()
        self.fixture["domains"].append({"id": "43", "dom": "child.test", "parent": "42", "home": str(self.root / "elsewhere"), "web": 1})
        result = self.run_adapter(reconcile=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["accounts"][0].get("unavailable"))

    def test_binding_attestation_detects_removed_or_duplicate_log(self):
        path = self.vhost()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_adapter(reconcile=False)
        row = json.loads(result.stdout)["accounts"][0]
        self.assertIs(row.get("binding_verified"), True)
        self.assertIsInstance(row.get("binding_started_at"), str)
        content = json.loads(path.read_text())
        private = content["logs"][0]
        content["logs"].insert(0, private)
        path.write_text(json.dumps(content))
        result = self.run_adapter(reconcile=False)
        self.assertIs(json.loads(result.stdout)["accounts"][0].get("binding_verified"), False)
        content["logs"] = ["/ordinary.log combined"]
        path.write_text(json.dumps(content))
        result = self.run_adapter(reconcile=False)
        self.assertIs(json.loads(result.stdout)["accounts"][0].get("binding_verified"), False)

    def test_healthy_binding_preserves_start_and_repair_resets_it(self):
        path = self.vhost()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        bindings = self.root / "state/bindings.json"
        state = json.loads(bindings.read_text())
        previous = "2000-01-01T00:00:00.000000+00:00"
        state["accounts"]["42"]["started_at"] = previous
        bindings.write_text(json.dumps(state))
        result = self.run_adapter(reconcile=False)
        self.assertEqual(json.loads(result.stdout)["accounts"][0]["binding_started_at"], previous)
        content = json.loads(path.read_text())
        content["logs"] = ["/ordinary.log combined"]
        path.write_text(json.dumps(content))
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_adapter(reconcile=False)
        row = json.loads(result.stdout)["accounts"][0]
        self.assertIs(row["binding_verified"], True)
        self.assertGreater(row["binding_started_at"], previous)

    def test_reconcile_is_idempotent_and_preserves_operator_hook(self):
        self.vhost()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("changed=0", result.stdout)
        self.assertEqual((self.root / "state/previous-hook").read_text(), "operator-hook")

    def test_unsupported_later_template_fails_before_native_mutation(self):
        path = self.vhost()
        before = path.read_text()
        self.fixture["templates"].append({"id": 7, "web": "ServerName ${DOM}"})
        result = self.run_adapter()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), before)
        self.assertFalse((self.native / "templates/0").exists())
        self.assertEqual(json.loads((self.native / "config").read_text())["post_command"], "operator-hook")

    def test_nested_child_database_is_included_once(self):
        self.vhost()
        self.vhost("43", "child.test")
        database = {"type": "mysql", "host": "localhost", "name": "shared"}
        self.fixture["domains"][0]["databases"] = [database]
        self.fixture["domains"].append({
            "id": "43", "dom": "child.test", "parent": "42", "home": str(self.root / "home/child"),
            "web": 1, "databases": [database],
        })
        result = self.run_adapter(reconcile=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)["accounts"][0]
        self.assertNotIn("unavailable", row)
        self.assertEqual(row["members"], ["42", "43"])
        self.assertEqual(row["mailboxes"], 0)
        self.assertEqual(row["databases"], [{"path": str(self.root / "database"), "bytes": 4096}])

    def test_unsupported_mail_keeps_valid_bandwidth_binding(self):
        self.vhost()
        self.fixture["domains"][0]["mail"] = 1
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_adapter(reconcile=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)["accounts"][0]
        self.assertNotIn("unavailable", row)
        self.assertIsNone(row["mailboxes"])
        self.assertEqual(row["databases"], [])
        self.assertIs(row["binding_verified"], True)

    def test_apache_template_update_preserves_notification_and_raw_settings(self):
        self.vhost()
        notification = self.native / "domain-template"
        notification.write_text("Unchanged operator notification")
        template = {"id": 7, "web": "ServerName ${DOM}\tCustomLog /other.log combined", "mail": "first\tsecond"}
        self.fixture["templates"].append(template)
        path = self.native / "templates/7"
        path.write_text(json.dumps(template))
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(notification.read_text(), "Unchanged operator notification")
        saved = json.loads(path.read_text())
        self.assertIn(f"v1 {INSTALLATION}", saved.pop("web"))
        self.assertEqual(saved, {"id": 7, "mail": "first\tsecond"})

    def test_busy_hook_defers_without_mutating_native_routes(self):
        path = self.vhost()
        before = path.read_text()
        with (self.root / "state/lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_adapter(mode="reconcile-hook")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "state/reconciliation-pending").exists())
        self.assertEqual(path.read_text(), before)

    def test_locked_refresh_repairs_pending_routes_without_reacquiring_lock(self):
        path = self.vhost()
        pending = self.root / "state/reconciliation-pending"
        pending.touch()
        with (self.root / "state/lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_adapter(mode="reconcile-locked")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"v1 {INSTALLATION} 42 ", json.loads(path.read_text())["logs"][0])
        self.assertFalse(pending.exists())

    def test_operator_hook_runs_and_keeps_status_when_telemetry_fails(self):
        telemetry = self.root / "telemetry.sh"
        telemetry.write_text("#!/bin/sh\nexit 19\n")
        marker = self.root / "operator-ran"
        previous = self.root / "state/previous-hook"
        previous.write_text(f"printf operator-ran > {shlex.quote(str(marker))}; exit 7")
        hook = self.root / "hook.sh"
        hook.write_text(HOOK.read_text().replace(
            "/usr/bin/perl /usr/local/libexec/praho-usage-metadata.pl", f"/bin/sh {shlex.quote(str(telemetry))}",
        ).replace("/var/lib/praho/usage", str(self.root / "state")))
        result = subprocess.run(  # noqa: S603 -- fixed shell and adapter created in the private test directory
            ["/bin/sh", str(hook)], capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertTrue(marker.exists())
        self.assertEqual(result.returncode, 7)

    def test_new_pending_event_survives_active_repair(self):
        self.vhost()
        (self.root / "state/reconciliation-pending").touch()
        self.fixture["event_during_reload"] = True
        result = self.run_adapter(mode="reconcile-locked")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "state/reconciliation-pending").read_text(), "concurrent")
        self.assertFalse((self.root / "state/reconciliation-processing").exists())

    def test_interrupted_repair_reloads_even_when_config_already_matches(self):
        self.vhost()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        reloads = self.root / "reloads"
        before = reloads.read_text().count("reload")
        (self.root / "state/reconciliation-processing").touch()
        result = self.run_adapter(mode="reconcile-locked")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(reloads.read_text().count("reload"), before + 1)
