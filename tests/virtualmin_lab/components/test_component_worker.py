"""Real leased Platform worker against an imported mixed source and a verified target.

Only public DNS discovery is adapted: the private disposable .test zone is read
from its actual authoritative BIND on D. Every admission, lease, archive transfer,
native action, bridge request and DNS write uses production code.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.infrastructure.dns_agreement import Agreement, RoutingAnswer
from apps.provisioning.component_migration_inspection import collect_source_components
from apps.provisioning.component_migration_service import (
    approve_component_review,
    record_component_review,
    release_source_obligation,
    start_component_migration,
)
from apps.provisioning.component_target_transport import target_operation_variables
from apps.provisioning.management.commands._virtualmin_lab import container_address, load_state
from apps.provisioning.migration_artifact_cleanup import cleanup_migration_artifacts
from apps.provisioning.migration_bridge_cleanup import cleanup_bridge
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminConfig
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security import acknowledge_source, connection_identity, record_inspection
from apps.provisioning.virtualmin_security_tasks import collect_inspection
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.virtualmin_lab.components.conftest import MixedSource
from tests.virtualmin_lab.components.site_observation import INSPECTION_ERROR_OBSERVATION
from tests.virtualmin_lab.components.test_source_coordinator import NATIVE_PREPARATION
from tests.virtualmin_lab.contract.harness import Lab, Recorder, RecordingGateway

DNS_PREPARATION = r"""
# Explicit disposable-fixture preparation BEFORE review: exact website source
# addresses and zero cache bounds, including negative AAAA responses. Retained
# MX/SPF/mail records are independent and remain unchanged after this point.
dns=r'''package virtual_server;
use JSON::PP qw(decode_json);my $p;{local $/;$p=decode_json(<STDIN>);}
$main::no_acl_check++;$ENV{'WEBMIN_CONFIG'}='/etc/webmin';$ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/modify-dns.pl';chdir('/usr/share/webmin/virtual-server') or die;
require './virtual-server-lib.pl';my $d=&get_domain($p->{'domain_id'});
die unless $d->{'dom'} eq $p->{'domain'} && $d->{'user'} eq $p->{'owner'};
&obtain_lock_dns($d);&pre_records_change($d);
my ($records,$file)=&get_domain_dns_records_and_file($d,1);my $apex=0;
foreach my $r (@$records) {
 if ($r->{'type'} eq 'SOA') {$r->{'values'}->[6]='0';$r->{'ttl'}=0;&modify_dns_record($records,$file,$r);}
 if ($r->{'name'} eq $p->{'domain'}.'.' && $r->{'type'} eq 'A') {
  die unless @{$r->{'values'}}==1;$r->{'values'}=[$p->{'source_ipv4'}];$r->{'ttl'}=0;
  &modify_dns_record($records,$file,$r);$apex++;
 }
 if ($r->{'name'} eq 'www.'.$p->{'domain'}.'.' && $r->{'type'} =~ /^(A|AAAA|CNAME)$/) {
  $r->{'values'}=[$p->{'source_ipv4'}] if $r->{'type'} eq 'A';
  $r->{'ttl'}=0;&modify_dns_record($records,$file,$r);
 }
}
die unless $apex==1;my $err=&post_records_change($d,$records,$file);die $err if $err;
&reload_bind_records($d);&after_records_change($d);&release_lock_dns($d);&run_post_actions();'''
prepared=subprocess.run(['/usr/bin/perl','-e',dns],input=json.dumps({**request,'source_ipv4':data['source_ipv4']}),
 capture_output=True,text=True,timeout=30)
assert prepared.returncode==0,'Explicit native fixture DNS preparation failed'
retained_probe.assert_retained_services(request['owner'],request['domain'],data['password'],retained_probe.unix_identity(request['owner']))
manifest=module.inspection.inspect_source(request)
assert not manifest['preparation'],manifest['preparation']
native_domain=module.inspection._fields(Path('/etc/webmin/virtual-server/domains')/request['domain_id'])
certificates={key:[native_domain[key],hashlib.sha256(Path(native_domain[key]).read_bytes()).hexdigest()]
 for key in ('ssl_cert','ssl_key','ssl_chain','ssl_combined','ssl_everything') if native_domain.get(key)}
print(json.dumps({'request':request,'manifest':manifest,'certificates':certificates,
 'unix_identity':retained_probe.unix_identity(request['owner'])}))
"""

SOURCE_CLEANUP = r"""
import importlib.util,json,sys
from pathlib import Path
data=json.load(sys.stdin);directory=Path(data['directory'])
def module(name):
 spec=importlib.util.spec_from_file_location(name,directory/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
bridge=module('praho-bridge').NodeBridge()
bridge.remove_source(data['operation_id'],domain=data['request']['domain'])
source=module('praho-component-native-source').NativeSource(data['request'],data['operation_id'],data['authority'])
if source.coordinator.journal.path.exists():
 # Fixture teardown deliberately destroys BOTH known disposable copies. It is
 # not production rollback, which cannot reopen a committed source.
 with source.coordinator.journal.locked():
  state=source.coordinator._state()
  if state['phase']!='retired':
   steps=source.coordinator._steps(state)
   owned=[*state['applied'],*([state['pending']] if state['pending'] else [])]
   for name in reversed(owned):steps[name].release()
   state['phase']='fixture_removed';source.coordinator.journal.write(state)
print('owned_source_fixture_holds_retired')
"""

SOURCE_RETIREMENT_DIAGNOSTIC = r"""
import importlib.util,json,sys
from pathlib import Path
d=json.load(sys.stdin)
result={'phase':None,'completed':None,'pending':None,'error_code':None}
try:
 path=Path(d['directory'])/'praho-component-journal.py'
 spec=importlib.util.spec_from_file_location('fixture_retirement_diagnostic',path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 journal=module.ComponentJournal(Path('/var/lib/praho/component-sources'),d['domain_id'],{
  'operation_id':d['operation_id'],'scope_digest':d['authority'],
  'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
 if journal.directory.resolve()!=journal.directory:raise ValueError('directory')
 if journal.directory.exists():module.ComponentJournal._private(journal.directory.lstat(),directory=True)
 state=journal.read()
 if state is None:
  result['error_code']='journal_missing'
 else:
  journal.assert_owned(state)
  phases={'applying','held','committing','committed','releasing','released','retiring','retired','fixture_removed'}
  steps={'web','database','paths','files','cron','ingress','export'}
  if state.get('phase') not in phases:raise ValueError('phase')
  result['phase']=state['phase']
  retirement=state.get('retirement')
  if retirement is not None:
   if not isinstance(retirement,dict):raise ValueError('retirement')
   completed=retirement.get('completed');pending=retirement.get('pending')
   if not isinstance(completed,list) or len(completed)>len(steps):raise ValueError('completed')
   if any(not isinstance(step,str) or step not in steps for step in completed):raise ValueError('completed')
   if pending is not None and (not isinstance(pending,str) or pending not in steps):raise ValueError('pending')
   result.update(completed=completed,pending=pending)
except Exception as error:
 result['error_code']=type(error).__name__
print(json.dumps(result,separators=(',',':')))
"""


@contextmanager
def _preserve_primary_failure_during_cleanup() -> Iterator[None]:
    primary = sys.exception()
    try:
        yield
    except Exception as error:
        if primary is None:
            raise
        primary.add_note("Component fixture cleanup also failed; error_code=" + type(error).__name__)


def _record_failure_before_cleanup(
    source: Lab, directory: str, request: dict, migration: VirtualminMigration, failure: BaseException
) -> None:
    """Expose only the safe bridge error and exact owned journal's bounded progress."""
    diagnostic = {}
    try:
        bridge = MigrationBridge.objects.filter(migration_id=migration.pk).first()
        last_error = bridge.evidence.get("last_error", "") if bridge is not None else ""
        if isinstance(last_error, str) and len(last_error) <= 4096:
            diagnostic["bridge_last_error"] = last_error
        else:
            diagnostic["bridge_error_code"] = "invalid_or_oversized"
        diagnostic["source_retirement"] = json.loads(
            _private_script(
                source,
                SOURCE_RETIREMENT_DIAGNOSTIC,
                {
                    "directory": directory,
                    "domain_id": request["domain_id"],
                    "operation_id": str(migration.pk),
                    "authority": migration.component_approval.review.authority_digest,
                },
                timeout=30,
            )
        )
    except Exception as error:
        diagnostic["diagnostic_error_code"] = type(error).__name__
    message = "PRAHO_COMPONENT_CLEANUP_FAILURE=" + json.dumps(diagnostic, ensure_ascii=True, separators=(",", ":"))
    print(message, flush=True)
    failure.add_note(message)


TARGET_CLEANUP = r"""
import importlib.util,json
from pathlib import Path
d=json.load(__import__('sys').stdin);directory=Path(d['directory'])
def module(name):
 spec=importlib.util.spec_from_file_location(name,directory/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
module('praho-bridge').NodeBridge().remove_origin(d['operation_id'])
m=module('praho-component-target');p=d['operation']
target=m.TargetCoordinator(d['manifest'],d['operation_id'],p['target_identity'],p['archive_sha256'],p['creation_params'])
if target.journal.path.exists():
 with target.journal.locked():
  state=target._state()
  if state['phase']=='removed':target._assert_absent(state)
  else:
   target._domain(state,held=state['phase'] not in {'active','policy_applying'})
   private=(m.archives.read_component_archive(target.archive,target.checksum,target.operation,target.manifest)
    if state.get('artifacts_phase')!='retired' else None)
   if state.get('web_sha256') and target._web(state).path.exists():
    if state.get('activation_web_sha256'):target._web(state).release_after_native_change(state['activation_web_sha256'])
    else:target._web(state).release()
   m.native('delete-domain',['--domain',target.domain]);target._assert_absent(state)
   if state['phase'] in {'restoring','held','sealed','activating','active','policy_applying'}:
    if target.manifest['databases']:
     if private is not None:target._sql(state,private).retire()
     else:
      sql=module('praho-component-mysql').native_sql
      assert sql("SELECT User FROM mysql.user WHERE User = '"+target.owner+"'")==[]
      for database in target.manifest['databases']:
       assert sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '"+database['name']+"'")==[]
    if state.get('web_sha256'):target._web(state).retire_after_domain_absence()
    target._pair('release',state)
    target._recovery().cleanup_staged(target.journal.directory,target.archive.parent,target.operation,target._identity(state))
   state['phase']='fixture_removed';target.journal.write(state)
print('owned_target_fixture_retired')
"""


def _install_helpers(lab: Lab, helpers: Path) -> str:
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-worker-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-worker-contract\.[A-Za-z0-9]+", directory)
    for path in (
        *helpers.glob("praho-component-*.py"),
        *helpers.glob("praho-component-*.pl"),
        helpers / "praho-apache-bindings.py",
        helpers / "praho-bridge.py",
        helpers / "praho-account-name-neutral.py",
        helpers / "praho-default-site.conf",
        helpers / "praho-recovery.py",
        helpers / "praho-recovery-ssl.py",
        helpers / "praho-recovery-credentials.pl",
        helpers / "praho-pair-restore.sh",
        helpers.parents[3] / "apps/provisioning/backup_owner_shadow.py",
        Path(__file__).with_name("retained_probe.py"),
    ):
        name = "praho_owner_shadow.py" if path.name == "backup_owner_shadow.py" else path.name
        result = subprocess.run(  # noqa: S603 -- exact owned lab and public helper code
            ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + name],  # noqa: S607
            input=path.read_text(),
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        assert result.returncode == 0, "Could not install the native worker fixture helpers"
        lab.exec("chmod", "700", directory + "/" + name)
    return directory


def _private_script(lab: Lab, script: str, payload: dict, *, timeout=240) -> str:
    result = subprocess.run(  # noqa: S603 -- literal owned fixture; credentials only through private stdin
        ["docker", "exec", "-i", lab.node.container, "python3", "-c", INSPECTION_ERROR_OBSERVATION + script],  # noqa: S607
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _assert_terminal_rollback(  # noqa: PLR0913 -- two exact native endpoints and their private fixture authority
    migration: VirtualminMigration,
    source: Lab,
    target: Lab,
    prepared: dict,
    source_directory: str,
    target_directory: str,
    spool: str,
) -> None:
    migration.account.refresh_from_db()
    assert migration.account.server_id == source.server.pk and migration.cutover_committed_at is None
    assert migration.restore_issued
    assert migration.barrier_state["component_target_removed"] and migration.barrier_state["component_source_released"]
    assert not MigrationBridge.objects.filter(migration=migration).exists()
    assert not hasattr(migration.component_source_obligation, "release")
    cleaned = cleanup_migration_artifacts(str(migration.pk))
    migration.refresh_from_db()
    assert cleaned["action"] == "cleaned", {"result": cleaned, "progress": migration.barrier_state.get("artifact_cleanup")}
    assert migration.barrier_state["artifact_cleanup"]["done"]
    assert not (Path(spool) / migration.archive_name).exists()
    proof = r"""
import hashlib,importlib.util,json,sys
from pathlib import Path
d=json.load(sys.stdin);root=Path(d['directory']);sys.path.insert(0,str(root));import retained_probe
def module(name):
 spec=importlib.util.spec_from_file_location(name,root/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('praho-component-native-source');s=m.NativeSource(d['request'],d['operation_id'],d['authority'])
state=s.coordinator.journal.read();assert state['phase']=='released' and state['export_retirement']=='retired'
assert not list(Path('/var/lib/praho-transfer/components',d['operation_id']).iterdir())
current=m.inspection._fields(Path('/etc/webmin/virtual-server/domains')/d['request']['domain_id'])
assert all(current[name]=='1' for name in ('web','ssl','mysql','mail','dns','unix'))
for key,(path,digest) in d['certificates'].items():
 assert current[key]==path and hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
sql=m.inspection.mysql.native_sql
assert sql('SELECT id,payload FROM `'+d['request']['owner']+'`.component_fixture')==[('1','selected application database')]
assert Path(d['manifest']['source']['home'],'public_html/component-db.php').is_file()
retained_probe.assert_retained_services(d['request']['owner'],d['request']['domain'],d['password'],d['unix_identity'])
print('actual_rollback_cleanup_preserves_original_source_services')
"""
    assert _private_script(
        source,
        proof,
        {
            **prepared, "directory": source_directory, "password": source.password,
            "operation_id": str(migration.pk), "authority": migration.component_approval.review.authority_digest,
        },
    ).strip() == "actual_rollback_cleanup_preserves_original_source_services"
    target_proof = r"""
import importlib.util,json
from pathlib import Path
d=json.load(__import__('sys').stdin);root=Path(d['directory'])
spec=importlib.util.spec_from_file_location('fixture_target',root/'praho-component-target.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);p=d['operation']
t=m.TargetCoordinator(d['manifest'],d['operation_id'],p['target_identity'],p['archive_sha256'],p['creation_params'])
state=t._state();assert state['phase']=='removed' and state['artifacts_phase']=='retired';t._assert_absent(state)
assert not t.archive.exists()
assert not (t.journal.directory/(t.operation+'.json')).exists()
assert not (t.journal.directory/(t.operation+'.cron')).exists()
print('actual_rollback_target_and_artifacts_removed')
"""
    assert _private_script(
        target,
        target_proof,
        {
            "directory": target_directory, "operation_id": str(migration.pk),
            "manifest": migration.component_approval.review.manifest,
            "operation": target_operation_variables(migration, migration.pk, "target_prepare")["component_operation"],
        },
    ).strip() == "actual_rollback_target_and_artifacts_removed"


def _native_dns(lab: Lab, domain: str, name: str, ipv4: str, ipv6: str | None = None, **_options) -> Agreement:
    assert name in {domain, "www." + domain}, "Only this private disposable zone may use the resolver adaptation"
    answers = []
    for kind in ("A", "AAAA"):
        raw = lab.exec("dig", "@127.0.0.1", "+noall", "+answer", "+authority", "+comments", name, kind)
        assert re.search(r"flags:[^;]*\baa\b", raw), "The fixture DNS answer is not authoritative"
        assert "status: NOERROR" in raw or "status: NXDOMAIN" in raw
        rows = [line.split() for line in raw.splitlines() if line and not line.startswith(";")]
        cname = next((row[4] for row in rows if len(row) >= 5 and row[3] == "CNAME"), "")
        if cname:
            assert name == "www." + domain and cname.rstrip(".") == domain
            terminal = lab.exec("dig", "@127.0.0.1", "+noall", "+answer", "+authority", "+comments", domain, kind)
            assert re.search(r"flags:[^;]*\baa\b", terminal)
            assert "status: NOERROR" in terminal
            rows += [line.split() for line in terminal.splitlines() if line and not line.startswith(";")]
        addresses = tuple(sorted(row[4] for row in rows if len(row) >= 5 and row[3] == kind))
        ttl = max((int(row[1]) for row in rows if len(row) >= 5), default=0)
        answers.append(
            RoutingAnswer(
                "native-source-authority",
                kind,
                addresses=addresses,
                ttl=ttl,
                server_address="127.0.0.1",
                queried_name=name,
                cname=cname,
            )
        )
    matched = set(answers[0].addresses) == {ipv4} and set(answers[1].addresses) == ({ipv6} if ipv6 else set())
    return Agreement(
        matched,
        max(answer.ttl for answer in answers),
        "" if matched else "Private authoritative routing has not converged",
        tuple(answers),
    )


@pytest.mark.usefixtures("native_target_site_observation")
@pytest.mark.parametrize("cancel_at_verifying", [False, True], ids=["completed_cleanup", "rollback_cleanup"])
def test_real_component_worker_uses_consumed_approval_and_preserves_imported_mail_dns_auth(  # noqa: C901, PLR0912, PLR0915 -- one real two-node lifecycle with exact failure cleanup
    mixed_source: MixedSource,
    cancel_at_verifying: bool,
) -> None:
    source = mixed_source.lab
    state = load_state()
    node = state.node("vm-b")
    target_server = VirtualminServer.objects.get(hostname=node.server_hostname)
    target = Lab(
        RecordingGateway(VirtualminConfig(server=target_server)),
        node,
        target_server,
        Recorder(version="8.3.0", directory=None),
        source.password,
    )
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    source_directory = _install_helpers(source, helpers)
    target_directory = _install_helpers(target, helpers)
    request = {
        "server_uuid": str(source.server.pk),
        "connection_identity": connection_identity(source.server),
        "domain_id": mixed_source.domain_id,
        "domain": mixed_source.domain,
        "owner": mixed_source.owner,
        "paths": [{"relative": "public_html", "purpose": "application"}],
        "databases": [],
    }
    original_servers = {
        server.pk: {
            field: getattr(server, field)
            for field in ("ipv4_address", "ipv6_address", "last_health_check", "current_domains")
        }
        for server in (source.server, target_server)
    }
    original_settings = {
        name: SettingsService.get_setting(name)
        for name in ("provisioning.migration_enabled", "provisioning.migration_spool_dir")
    }
    migration = None
    actor = None
    temporary_root = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="praho-worker-native-", dir=temporary_root) as temporary:
        try:
            for lab in (source, target):
                assert lab.gateway.call("info", {"multiline": ""}).is_ok()
                lab.server.ipv4_address = container_address(lab.node.container)
                lab.server.ipv6_address = ""
                lab.server.last_health_check = timezone.now()
                lab.server.save(update_fields=["ipv4_address", "ipv6_address", "last_health_check"])
            assert destination_refusal(target_server) is None, (
                "Use an actually verified destination; never fabricate capability"
            )
            prepared = json.loads(
                _private_script(
                    source,
                    NATIVE_PREPARATION + DNS_PREPARATION,
                    {
                        "directory": source_directory,
                        "request": request,
                        "password": source.password,
                        "source_ipv4": source.server.ipv4_address,
                    },
                )
            )
            request = prepared["request"]
            for name in (mixed_source.domain, "www." + mixed_source.domain):
                initial = _native_dns(source, mixed_source.domain, name, source.server.ipv4_address)
                assert initial.agreed, "Explicit fixture routing did not reach its source: " + str(initial)
                assert initial.ttl <= 1, "Disposable fixture DNS cache bounds must be zero before its first publication"
            actor = User.objects.create_user(
                email=mixed_source.owner + "-operator@praho.test", password=None, is_staff=True, is_superuser=True
            )
            security = collect_inspection(source.server)
            source_review = record_inspection(source.server, security)
            acknowledge_source(
                source_review,
                security,
                actor,
                "Disposable mixed-source qualification: retain native mail, DNS and Unix authentication.",
            )
            source.server.refresh_from_db()
            service = Service.objects.create(
                customer=Customer.objects.get(primary_email="lab@praho.test"),
                service_plan=ServicePlan.objects.get(name="Virtualmin lab hosting"),
                currency=Currency.objects.get(code="RON"),
                service_name=mixed_source.domain,
                domain=mixed_source.domain,
                username=mixed_source.owner,
                billing_cycle="monthly",
                price=Decimal("0.00"),
                status="pending",
            )
            account = VirtualminAccount(
                service=service,
                server=source.server,
                domain=mixed_source.domain,
                virtualmin_username=mixed_source.owner,
                domains=[mixed_source.domain],
                status="active",
                disk_quota_mb=1024,
                bandwidth_quota_mb=10240,
            )
            account.set_password(source.password)
            account.save()
            # fsm-bypass: fixture linkage adopts its already-running native source; no provision task is appropriate.
            Service.objects.filter(pk=service.pk).update(status="active")
            for name, value in (
                ("provisioning.migration_enabled", True),
                ("provisioning.migration_spool_dir", str(Path(temporary).resolve())),
            ):
                changed = SettingsService.update_setting(name, value)
                assert changed.is_ok(), changed
            selection = {key: request[key] for key in ("domain_id", "domain", "owner", "paths", "databases")}
            facts = collect_source_components(source.server, selection)
            facts.assert_ready()
            review = record_component_review(account, target_server, facts.as_json(), actor)
            approval = approve_component_review(
                review,
                facts.as_json(),
                actor,
                "Move selected PHP/files/SQL and website routing; keep source mail/DNS/Unix auth and their backup responsibility.",
                "This disposable fixture retains no customer data; owned teardown removes it after native preservation proof.",
            )
            migration = start_component_migration(approval, facts.as_json(), actor, enqueue=False)
            mixed_source.cleanup_callbacks.append(
                lambda: release_source_obligation(
                    migration.component_source_obligation,
                    actor,
                    "Disposable worker fixture: exact native source domain and owner removed; no customer data or retained backup remains.",
                )
            )

            def authority(name, ipv4, ipv6=None, **options):
                return _native_dns(source, mixed_source.domain, name, ipv4, ipv6, **options)

            terminal = "rolled_back" if cancel_at_verifying else "completed"
            with patch("apps.provisioning.migration_routing.routing_agreement", side_effect=authority):
                for _checkpoint in range(18):
                    outcome = VirtualminMigrationService().run(migration.pk)
                    assert outcome.is_ok(), outcome
                    migration.refresh_from_db()
                    assert migration.status != "needs_review", migration.error_detail
                    if migration.status == terminal:
                        break
                    assert migration.status not in {"completed", "failed", "rolled_back"}, migration.error_detail
                    if cancel_at_verifying and migration.status == "verifying":
                        assert migration.cutover_committed_at is None
                        assert not migration.barrier_state.get("component_source_seal_intent")
                        assert VirtualminMigration.objects.filter(pk=migration.pk, status="verifying").update(
                            cancel_requested=True
                        ) == 1
                    if migration.resume_after is not None:
                        time.sleep(min(2, max(0, (migration.resume_after - timezone.now()).total_seconds()) + 0.05))
                assert migration.status == terminal, "Native worker did not converge within its bounded checkpoints"
            if cancel_at_verifying:
                _assert_terminal_rollback(migration, source, target, prepared, source_directory, target_directory, temporary)
                return
            account.refresh_from_db()
            assert account.server_id == target_server.pk
            assert migration.component_approval_id == approval.pk
            assert migration.component_source_obligation.source_server_id == source.server.pk
            assert not hasattr(migration.component_source_obligation, "release")
            bridge = MigrationBridge.objects.get(migration=migration)
            assert bridge.status == "active" and bridge.evidence["component_source_retained"]
            assert migration.barrier_state["component_routing"]["routing"] == "source_dns_updated"
            assert _native_dns(source, mixed_source.domain, mixed_source.domain, target_server.ipv4_address).agreed
            proof = r"""
import importlib.util,json,sys
from pathlib import Path
d=json.load(sys.stdin);sys.path.insert(0,d['directory']);import retained_probe
retained_probe.assert_retained_services(d['request']['owner'],d['request']['domain'],d['password'],d['unix_identity'])
print('retained_native_services_verified')
"""
            assert (
                _private_script(
                    source, proof, {**prepared, "directory": source_directory, "password": source.password}
                ).strip()
                == "retained_native_services_verified"
            )
            public = target.exec(
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--noproxy",
                "*",
                "--resolve",
                mixed_source.domain + ":80:127.0.0.1",
                "http://" + mixed_source.domain + "/component-db.php",
            )
            assert json.loads(public)["proof"] == "selected-sql-and-php"
            assert json.loads(public)["rows"] == 1
            assert json.loads(public)["uid"] == int(target.exec("id", "-u", mixed_source.owner).strip()) > 0
            # Explicitly advance only the disposable fixture retention deadline;
            # fresh real authority/cache observations still gate the actual worker.
            bridge.evidence = {
                **bridge.evidence,
                "expires_at": (timezone.now() - timedelta(seconds=1)).isoformat(),
                "next_run": timezone.now().isoformat(),
            }
            bridge.save(update_fields=["evidence", "updated_at"])
            with patch("apps.provisioning.migration_routing.routing_agreement", side_effect=authority):
                cleanup = cleanup_bridge(str(migration.pk))
            bridge.refresh_from_db()
            assert cleanup["action"] == "torn_down", {"result": cleanup, "evidence": bridge.evidence}
            assert bridge.status == "torn_down" and bridge.evidence["source_services_retained"]
            assert bridge.evidence["source_components_removed"] and bridge.evidence["target_artifacts_retired"]
            assert not hasattr(migration.component_source_obligation, "release")
            assert not (Path(temporary) / migration.archive_name).exists()
            retirement_proof = r"""
import hashlib,importlib.util,json,sys
from pathlib import Path
d=json.load(sys.stdin);root=Path(d['directory']);sys.path.insert(0,str(root));import retained_probe
def module(name):
 spec=importlib.util.spec_from_file_location(name,root/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('praho-component-native-source');s=m.NativeSource(d['request'],d['operation_id'],d['authority'])
assert s.coordinator.journal.read()['phase']=='retired'
current=m.inspection._fields(Path('/etc/webmin/virtual-server/domains')/d['request']['domain_id'])
assert current['web']=='0' and current['ssl']=='0' and current['mysql']=='0' and current['db_mysql']==''
assert current['mail']=='1' and current['dns']=='1' and current['unix']=='1'
for key,(path,digest) in d['certificates'].items():
 assert current[key]==path and hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
home=Path(d['manifest']['source']['home']);assert not (home/'public_html').exists() and (home/'Maildir').is_dir()
assert not list(Path('/etc/php').glob('*/fpm/pool.d/'+d['request']['domain_id']+'.conf'))
assert not Path('/etc/apache2/conf-enabled/praho-z-component-'+d['request']['domain_id']+'.conf').exists()
sql=m.inspection.mysql.native_sql
assert sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '"+d['request']['owner']+"'")==[]
assert sql("SELECT User FROM mysql.user WHERE User = '"+d['request']['owner']+"'")==[]
assert not list(Path('/var/lib/praho-transfer/components',d['operation_id']).iterdir())
bridge=module('praho-bridge').NodeBridge();directory=bridge.directory(d['operation_id'])
assert (directory/'source-removed').exists() and not (directory/'source.json').exists()
assert not (bridge.conf/('praho-migration-'+d['operation_id']+'.conf')).exists()
assert not list(directory.glob('source-*-*.pem')) and not (directory/'upstream-ca.pem').exists()
retained_probe.assert_retained_services(d['request']['owner'],d['request']['domain'],d['password'],d['unix_identity'])
print('actual_cleanup_preserves_retained_native_services')
"""
            assert _private_script(
                source,
                retirement_proof,
                {
                    **prepared, "directory": source_directory, "password": source.password,
                    "operation_id": str(migration.pk), "authority": approval.review.authority_digest,
                },
            ).strip() == "actual_cleanup_preserves_retained_native_services"
            target_retirement_proof = r"""
import importlib.util,json
from pathlib import Path
d=json.load(__import__('sys').stdin);directory=Path(d['directory'])
spec=importlib.util.spec_from_file_location('fixture_bridge',directory/'praho-bridge.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);bridge=m.NodeBridge();owned=bridge.directory(d['operation_id'])
assert (owned/'origin-removed').exists()
assert not (bridge.conf/('praho-origin-'+d['operation_id']+'.conf')).exists()
for name in ('origin.json','origin-target.json','origin.pem','origin-key.pem'):
 assert not (owned/name).exists()
assert not Path('/var/lib/praho-transfer','migration_'+d['operation_id']+'.tar.gz').exists()
print('actual_target_private_artifacts_retired')
"""
            assert _private_script(
                target, target_retirement_proof, {"directory": target_directory, "operation_id": str(migration.pk)}
            ).strip() == "actual_target_private_artifacts_retired"
            assert json.loads(target.exec(
                "curl", "--silent", "--show-error", "--fail", "--noproxy", "*", "--resolve",
                mixed_source.domain + ":80:127.0.0.1", "http://" + mixed_source.domain + "/component-db.php",
            )) == json.loads(public), "Final private artifact retirement changed the live target application"
        finally:
            primary_failure = sys.exception()
            if primary_failure is not None and migration is not None:
                _record_failure_before_cleanup(source, source_directory, request, migration, primary_failure)
            with _preserve_primary_failure_during_cleanup():
                if migration is not None:
                    migration.refresh_from_db()
                    _private_script(
                        source,
                        SOURCE_CLEANUP,
                        {
                            "directory": source_directory,
                            "request": request,
                            "operation_id": str(migration.pk),
                            "authority": migration.component_approval.review.authority_digest,
                        },
                    )
                    if migration.restore_issued:
                        operation = target_operation_variables(migration, migration.pk, "target_prepare")[
                            "component_operation"
                        ]
                        _private_script(
                            target,
                            TARGET_CLEANUP,
                            {
                                "directory": target_directory,
                                "manifest": migration.component_approval.review.manifest,
                                "operation_id": str(migration.pk),
                                "operation": operation,
                            },
                        )
                    bridge = MigrationBridge.objects.filter(migration=migration).first()
                    if bridge is not None and bridge.status not in {"failed", "torn_down"}:
                        bridge.fail()
                        bridge.evidence = {
                            **bridge.evidence,
                            "last_error": "Disposable native fixture explicitly retired both owned nodes and transport after proof",
                        }
                        bridge.save()
                    if migration.status not in {"completed", "failed", "rolled_back"}:
                        # fsm-bypass: explicit owned-lab teardown after preserving failure evidence above.
                        VirtualminMigration.objects.filter(pk=migration.pk).update(
                            status="failed", lease_token=None, worker_lease_expires_at=None
                        )
                    # fsm-bypass: exact disposable native target was removed; preserve its historical Platform rows.
                    Service.objects.filter(pk=migration.account.service_id).update(status="terminated")
                    VirtualminAccount.objects.filter(pk=migration.account_id).update(status="terminated")
                for server in (source.server, target_server):
                    for name, value in original_servers[server.pk].items():
                        setattr(server, name, value)
                    server.save(update_fields=[*original_servers[server.pk], "updated_at"])
                for name, value in original_settings.items():
                    restored = (
                        value
                        if value is not None
                        else (False if name.endswith("enabled") else "/var/lib/praho/migration-spool")
                    )
                    assert SettingsService.update_setting(name, restored).is_ok()
                source.exec("rm", "-rf", "--", source_directory)
                target.exec("rm", "-rf", "--", target_directory)
