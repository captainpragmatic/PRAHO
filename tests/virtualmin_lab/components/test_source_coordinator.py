"""The complete native source hold preserves mail/DNS/authentication across compensation."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

from apps.provisioning.virtualmin_security import connection_identity
from tests.virtualmin_lab.components.conftest import MixedSource

NATIVE_PREPARATION = r"""
import hashlib,importlib.util,json,os,re,subprocess,sys,tarfile,time
from pathlib import Path
from uuid import uuid4
data=json.load(sys.stdin);root=Path(data['directory']);request=data['request']
sys.path.insert(0,str(root));import retained_probe
def run(arguments):
 result=subprocess.run(arguments,capture_output=True,text=True,timeout=120)
 assert result.returncode==0,'Explicit fixture preparation failed: '+result.stderr
 return result.stdout
# Explicit operator preparation happens before review: retire unused admin/webmail
# HTTP redirects, disable unselected CGI, and publish independent mail SPF.
run(['virtualmin','modify-web','--domain',request['domain'],'--no-webmail','--disable-cgi'])
site=Path('/etc/apache2/sites-available')/(request['domain']+'.conf')
original=site.read_text()
def aliases(match):
 names=[name for name in match.group(1).split() if name in {request['domain'],'www.'+request['domain']}]
 return 'ServerAlias '+' '.join(names) if names else ''
site.write_text(re.sub(r'^\s*ServerAlias\s+(.+)$',aliases,original,flags=re.M))
run(['apache2ctl','configtest']);run(['systemctl','reload','apache2'])
txt=run(['dig','+short','@127.0.0.1',request['domain'],'TXT']).splitlines()
assert len(txt)==1 and txt[0].startswith('"v=spf1 '),'Fixture SPF cannot be edited unambiguously'
spf=r'''package virtual_server;
$main::no_acl_check++;$ENV{'WEBMIN_CONFIG'}='/etc/webmin';$ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/modify-dns.pl';
chdir('/usr/share/webmin/virtual-server') or die 'native module unavailable';
require './virtual-server-lib.pl';&require_bind();
my $d=&get_domain_by('dom',$ARGV[0]);
die 'foreign fixture owner' unless $d->{'user'} eq $ARGV[1];
&obtain_lock_dns($d);&save_domain_spf($d,{'mx'=>1,'all'=>3});&release_lock_dns($d);
&run_post_actions();'''
run(['perl','-e',spf,request['domain'],request['owner']])
deadline=time.monotonic()+15
while True:
 actual=run(['dig','+short','@127.0.0.1',request['domain'],'TXT']).splitlines()
 if actual==['"v=spf1 mx -all"']:break
 assert time.monotonic()<deadline,('Prepared SPF did not become authoritative',actual)
 time.sleep(0.2)
spec=importlib.util.spec_from_file_location('native_source',root/'praho-component-native-source.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
# Explicit fixture/operator preparation before review. Named virtual hosts keep
# their behavior; unknown hostnames now get the neutral404 default. Component
# holds must never introduce this global binding policy implicitly.
bindings=module.inspection.defaults.apache.ApacheBindings()
default=Path('/etc/apache2/conf-enabled/praho-default-site.conf')
prepared=(root/'praho-default-site.conf').read_bytes()
Path('/var/www/praho-default').mkdir(mode=0o755,parents=True,exist_ok=True)
with bindings.transaction({default:0o644}):
 # This owned disposable source is explicitly upgraded BEFORE operator review.
 bindings.write(default,prepared,0o644)
 bindings.refresh();bindings.reload()
assert not module.inspection.defaults.qualify_default(),'Explicit neutral default preparation failed'
private_file=Path('/home')/request['owner']/'public_html/root-private'
private_file.write_bytes(b'component source root-private fixture')
private_file.chmod(0o600)
(private_file.parent/'component-proof.txt').write_text('selected component frontend proof')
# An operator explicitly selects the native application's schema and replaces
# unused future-schema wildcard grants before reviewing the mixed-service source.
sql=module.inspection.mysql.native_sql
owner=request['owner']
hosts=sql("SELECT Host FROM mysql.user WHERE User = '"+owner+"' ORDER BY Host")
assert hosts
for host, in hosts:
 assert module.inspection.mysql.HOST.fullmatch(host)
 assert re.fullmatch(r'[A-Za-z0-9]+',data['password'])
 sql("ALTER USER '"+owner+"'@'"+host+"' IDENTIFIED BY 'SQL"+data['password']+"'")
 sql("REVOKE ALL PRIVILEGES, GRANT OPTION FROM '"+owner+"'@'"+host+"'")
 sql("GRANT ALL PRIVILEGES ON "+module.inspection.mysql.exact_schema(owner)+".* TO '"+owner+"'@'"+host+"'")
sql('CREATE TABLE `'+owner+'`.component_fixture (id INT PRIMARY KEY, payload VARCHAR(80))')
sql("INSERT INTO `"+owner+"`.component_fixture VALUES(1,'selected application database')")
request['databases']=[owner]
# Explicitly repair the fixture's native SQL credential metadata as an operator
# would before review. This selected credential differs from retained Unix/mail.
native_profile=r'''package virtual_server;
use JSON::PP qw(decode_json);my $p;{local $/;$p=decode_json(<STDIN>);}
$main::no_acl_check++;$ENV{'WEBMIN_CONFIG'}='/etc/webmin';$ENV{'WEBMIN_VAR'}='/var/webmin';
$0='/usr/share/webmin/virtual-server/modify-domain.pl';chdir('/usr/share/webmin/virtual-server') or die;
require './virtual-server-lib.pl';my $d=&get_domain_by('dom',$p->{'domain'});die unless $d->{'user'} eq $p->{'owner'};
&lock_domain($d->{'id'});$d->{'mysql_pass'}=$p->{'sql_password'};&save_domain($d);&unlock_domain($d->{'id'});'''
profile=subprocess.run(['/usr/bin/perl','-e',native_profile],input=json.dumps({'domain':request['domain'],
 'owner':owner,'sql_password':'SQL'+data['password']}),capture_output=True,text=True,timeout=30)
assert profile.returncode==0,'Explicit source native credential preparation failed'
login=subprocess.run(['/usr/bin/mysql','--batch','--skip-column-names','--user',owner,'--database',owner],
 input='SELECT payload FROM component_fixture;\n',env={**os.environ,'MYSQL_PWD':'SQL'+data['password']},
 capture_output=True,text=True,timeout=15)
assert login.returncode==0 and login.stdout.strip()=='selected application database','Source application SQL fixture is not usable'
application=private_file.parent/'component-db.php'
application.write_text("<?php\ntry { $db=new PDO('mysql:host=localhost;dbname="+owner+"','"+owner+"','SQL"+data['password']+"'); "
 "echo json_encode(['proof'=>'selected-sql-and-php','rows'=>(int)$db->query('SELECT COUNT(*) FROM component_fixture')->fetchColumn(),"
 "'uid'=>posix_geteuid()]); } catch (Throwable $error) { http_response_code(500); echo 'Application probe failed'; }\n")
os.chown(application,0,module.inspection.pwd.getpwnam(owner).pw_gid);application.chmod(0o640)
"""

NATIVE_PROOF = (
    NATIVE_PREPARATION
    + r"""
manifest=module.inspection.inspect_source(request)
assert not manifest['preparation'],manifest['preparation']
source=module.NativeSource(request,str(uuid4()),module.authority_digest(manifest))
identity=retained_probe.unix_identity(request['owner'])
before=site.read_bytes()
try:
 retained_probe.assert_retained_services(request['owner'],request['domain'],data['password'],identity)
 source.coordinator.apply();source.coordinator.verify();source.coordinator.apply()
 assert site.read_bytes()==before,'Source hold changed native domain configuration'
 # Recreate the coordinator from its exact durable context, as a retried worker does.
 resumed=module.NativeSource(request,source.operation,source.authority)
 resumed.coordinator.verify()
 export_spec=importlib.util.spec_from_file_location('source_export',root/'praho-component-source-export.py')
 exporter=importlib.util.module_from_spec(export_spec);export_spec.loader.exec_module(exporter)
 exported=exporter.export_source(resumed)
 archive=Path(exported['path'])
 assert hashlib.sha256(archive.read_bytes()).hexdigest()==exported['sha256']
 with tarfile.open(archive) as bundle:
  private=json.load(bundle.extractfile(request['domain']+'_virtualmin_components'))
  assert private['manifest']['paths'][0]['relative']=='public_html'
  assert {(row['user'],row['host']) for row in private['principals']}=={(owner,host[0]) for host in hosts}
  assert all('Maildir' not in row['relative'] for row in private['files'])
  metadata=bundle.extractfile(request['domain']+'_virtualmin').read()
  assert b'praho_backup_owner_shadow_v1=' in metadata
  assert b'mail=0\n' in metadata and b'dns=0\n' in metadata and b'mysql_pass=SQL' in metadata
 assert exporter.export_source(resumed)==exported,'A retried export changed its immutable published receipt'
 retained_probe.assert_retained_services(request['owner'],request['domain'],data['password'],identity)
 resumed.coordinator.release();resumed.coordinator.release()
 assert site.read_bytes()==before
 retained_probe.assert_retained_services(request['owner'],request['domain'],data['password'],identity)
 print(json.dumps({'all_native_holds_verified':True,'retained_services_preserved':True,'compensation_verified':True,
  'export':exported,'manifest':manifest,'operation_id':source.operation}))
finally:
 if source.coordinator.journal.path.exists():source.coordinator.release()
"""
)

TARGET_PROOF = r"""
import importlib.util,json,os,subprocess,sys
from pathlib import Path
data=json.load(sys.stdin);directory=Path(data['directory'])
spec=importlib.util.spec_from_file_location('target_prepare',directory/'praho-component-target.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
manifest=data['manifest'];source=manifest['source']
parameters={'domain':source['domain'],'user':source['owner'],'template':'Default Settings',
 'desc':'Disposable component target qualification',**dict.fromkeys(module.FEATURES,'')}
target=module.TargetCoordinator(manifest,data['operation_id'],'a'*64,data['export']['sha256'],parameters)
created=None
try:
 created=target.prepare()
 assert target.prepare()==created
 assert created['phase']=='prepared' and created['target_domain_id'].isdecimal()
 restored=target.restore()
 assert restored['phase']=='held'
 private_file=Path(source['home'])/'public_html/root-private'
 assert private_file.read_bytes()==b'component source root-private fixture'
 assert private_file.stat().st_uid==0 and private_file.stat().st_mode & 0o777==0o600
 assert target.restore()==restored
 sql=module.preflight.mysql.native_sql
 assert sql('SELECT id,payload FROM `'+source['owner']+'`.component_fixture')==[('1','selected application database')]
 target._sql(target._state(),module.archives.read_component_archive(target.archive,target.checksum,target.operation,manifest)).verify()
 def application_login():
  return subprocess.run(['/usr/bin/mysql','--batch','--skip-column-names','--user',source['owner'],
   '--database',source['owner']],input='SELECT payload FROM component_fixture;\n',
   env={**os.environ,'MYSQL_PWD':'SQL'+data['password']},capture_output=True,text=True,timeout=15)
 assert application_login().returncode!=0,'Held target accepted an application login'
 if not data['activate']:
  removed=target.remove()
  assert removed['phase']=='removed' and target.remove()==removed
  assert not target._web(target._state()).path.exists()
  assert sql("SELECT User FROM mysql.user WHERE User = '"+source['owner']+"'")==[]
  assert not (Path('/etc/webmin/virtual-server/domains')/created['target_domain_id']).exists()
  created=None
  print(json.dumps({'target_compensated_with_exact_native_absence':True,'component_guard_and_sql_receipts_retired':True}))
  sys.exit(0)
 sealed=target.seal(restored['target_receipt_sha256'])
 assert sealed['phase']=='sealed' and target.seal(restored['target_receipt_sha256'])==sealed
 try:target.remove()
 except ValueError as error:assert 'committed' in str(error)
 else:raise AssertionError('A late rollback deleted a sealed target')
 active=target.activate(restored['target_receipt_sha256'],enabled=True)
 assert active['phase']=='active'
 assert target.activate(restored['target_receipt_sha256'],enabled=True)==active
 assert target.reconcile_policy(enabled=False)==active
 assert application_login().returncode!=0,'Current policy did not lock the selected SQL login'
 assert target.reconcile_policy(enabled=True)==active
 assert application_login().returncode==0,'Current policy replay changed the selected SQL credential'
 assert sql('SELECT id,payload FROM `'+source['owner']+'`.component_fixture')==[('1','selected application database')]
 private=module.archives.read_component_archive(target.archive,target.checksum,target.operation,manifest)
 target._sql(target._state(),private).verify(active=True)
 assert not target._domain(target._state(),held=False).get('disabled')
 assert not target._web(target._state()).path.exists()
 logged_in=application_login()
 assert logged_in.returncode==0 and logged_in.stdout.strip()=='selected application database','Activated application SQL login failed'
 assert target._domain(target._state(),held=False).get('pass','')==''
 module.native('disable-domain',['--domain',source['domain']])
 assert application_login().returncode!=0,'Ordinary billing suspension left application SQL login usable'
 suspended=target._domain(target._state(),held=True)
 saved_hashes={row['authentication_string'] for row in private['principals'] if row['user']==source['owner']}
 suspension_evidence={'saved_original_sql_hash':suspended.get('disabled_oldmysql') in saved_hashes,
  'native_unix_plaintext_empty':not suspended.get('pass'),
  'native_selected_sql_password':suspended.get('mysql_pass')=='SQL'+data['password'],
  'native_hash_selected':suspended.get('mysql_enc_pass') in saved_hashes}
 module.native('enable-domain',['--domain',source['domain']])
 resumed_login=application_login()
 assert resumed_login.returncode==0 and resumed_login.stdout.strip()=='selected application database',suspension_evidence
 assert target.activate(restored['target_receipt_sha256'],enabled=True)==active
 ingress=target._web(target._state());bindings=ingress._state()['bindings']
 for address in ingress.bindings.probe_addresses(bindings,'80'):
  resolved='['+address+']' if ':' in address else address
  probe=module.archives.source.inspection._command(['/usr/bin/curl','--silent','--show-error','--noproxy','*',
   '--resolve',source['domain']+':80:'+resolved,'--dump-header','-','--max-time','10',
   'http://'+source['domain']+'/component-proof.txt'])
  assert 'X-PRAHO-Component-Hold' not in probe and 'selected component frontend proof' in probe
  application=module.archives.source.inspection._command(['/usr/bin/curl','--silent','--show-error','--fail','--noproxy','*',
   '--resolve',source['domain']+':80:'+resolved,'--max-time','10','http://'+source['domain']+'/component-db.php'])
  assert json.loads(application)=={'proof':'selected-sql-and-php','rows':1,'uid':target._state()['target_uid']}
 print(json.dumps({'fresh_target_owned_and_disabled':True,'selected_files_restored_with_root600_preserved':True,
  'selected_database_restored_with_held_credentials':True,'native_activation_preserves_application_authentication':True}))
except Exception:
 if created:
  progress=Path('/run/praho')/('pair-'+created['target_domain_id']+'.progress')
  if progress.is_file():print('PUBLIC_PAIR_CHECKPOINTS='+progress.read_text(),file=sys.stderr)
 raise
finally:
 if created:
  with target.journal.locked():
   state=target._state();target._domain(state,held=state['phase'] not in {'activating','active'})
   if state.get('web_sha256') and target._web(state).path.exists():
    if state.get('activation_web_sha256'):target._web(state).release_after_native_change(state['activation_web_sha256'])
    else:target._web(state).release()
   module.native('delete-domain',['--domain',source['domain']])
   assert not (Path('/etc/webmin/virtual-server/domains')/created['target_domain_id']).exists()
   if state['phase'] in {'restoring','held','sealed','activating','active','policy_changing'}:
    target._pair('release',state)
    target._recovery().cleanup_staged(target.journal.directory,target.archive.parent,target.operation,target._identity(state))
   state['phase']='fixture_removed';target.journal.write(state)
"""


def prepare_native_target(exported: dict, helpers: Path, password: str, *, activate: bool) -> None:
    target = "vmlab-b"
    root = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="praho-component-transfer-", dir=root) as temporary:
        archive = Path(temporary) / ("migration_" + exported["operation_id"] + ".tar.gz")
        copied = subprocess.run(  # noqa: S603 -- exact owned source export, into a private controller directory
            ["docker", "cp", "vmlab-component-source:" + exported["export"]["path"], str(archive)],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert copied.returncode == 0
        archive.chmod(0o600)

        def execute(*arguments):
            result = subprocess.run(  # noqa: S603 -- only the known disposable target and literal helper operations
                ["docker", "exec", target, *arguments],  # noqa: S607 -- installed lab runtime
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert result.returncode == 0, "Native disposable target preparation failed"
            return result.stdout.strip()

        directory = execute("mktemp", "-d", "/var/lib/praho-target-prepare.XXXXXXXX")
        assert re.fullmatch(r"/var/lib/praho-target-prepare\.[A-Za-z0-9]+", directory)
        execute("mkdir", "-p", "/var/lib/praho-transfer")
        execute("chmod", "700", "/var/lib/praho-transfer")
        remote = "/var/lib/praho-transfer/" + archive.name
        execute("test", "!", "-e", remote)
        execute("test", "!", "-L", remote)
        try:
            moved = subprocess.run(  # noqa: S603 -- immutable fixture archive, exact newly selected target path
                ["docker", "cp", str(archive), target + ":" + remote],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert moved.returncode == 0
            execute("chown", "root:root", remote)
            execute("chmod", "600", remote)
            for path in (
                *helpers.glob("praho-component-*.py"),
                helpers / "praho-apache-bindings.py",
                helpers / "praho-component-native-command.pl",
                helpers / "praho-component-policy.pl",
                helpers / "praho-recovery.py",
                helpers / "praho-recovery-ssl.py",
                helpers / "praho-recovery-credentials.pl",
                helpers / "praho-pair-restore.sh",
                helpers.parents[3] / "apps/provisioning/backup_owner_shadow.py",
            ):
                destination = "praho_owner_shadow.py" if path.name == "backup_owner_shadow.py" else path.name
                installed = subprocess.run(  # noqa: S603 -- public code into the exact target fixture directory
                    ["docker", "exec", "-i", target, "tee", directory + "/" + destination],  # noqa: S607
                    input=path.read_text(),
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                assert installed.returncode == 0
                execute("chmod", "700", directory + "/" + destination)
            proof = subprocess.run(  # noqa: S603 -- private target preparation, public receipt only
                ["docker", "exec", "-i", target, "python3", "-c", TARGET_PROOF],  # noqa: S607
                input=json.dumps({**exported, "directory": directory, "password": password, "activate": activate}),
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
            assert proof.returncode == 0, proof.stderr
            expected = {
                "fresh_target_owned_and_disabled": True,
                "selected_files_restored_with_root600_preserved": True,
                "selected_database_restored_with_held_credentials": True,
                "native_activation_preserves_application_authentication": True,
            }
            if not activate:
                expected = {
                    "target_compensated_with_exact_native_absence": True,
                    "component_guard_and_sql_receipts_retired": True,
                }
            assert json.loads(proof.stdout) == expected
        finally:
            execute("rm", "-f", "--", remote)
            execute("rm", "-rf", "--", directory)


@pytest.mark.usefixtures("native_target_site_observation")
@pytest.mark.parametrize("activate_target", [False, True])
def test_native_source_coordinator_preserves_retained_services(
    mixed_source: MixedSource, activate_target: bool
) -> None:
    lab = mixed_source.lab
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-source-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-source-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    files = [
        *helpers.glob("praho-component-*.py"),
        helpers / "praho-apache-bindings.py",
        helpers / "praho-recovery-credentials.pl",
        helpers / "praho-default-site.conf",
    ]
    files.append(Path(__file__).with_name("retained_probe.py"))
    try:
        for path in files:
            copied = subprocess.run(  # noqa: S603 -- public helper code into an exact disposable fixture directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + path.name],  # noqa: S607
                input=path.read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0, "Could not install the native component source helper"
        result = subprocess.run(  # noqa: S603 -- disposable source; private password only through stdin
            ["docker", "exec", "-i", lab.node.container, "python3", "-c", NATIVE_PROOF],  # noqa: S607
            input=json.dumps(
                {
                    "directory": directory,
                    "password": lab.password,
                    "request": {
                        "server_uuid": str(lab.server.pk),
                        "connection_identity": connection_identity(lab.server),
                        "domain_id": mixed_source.domain_id,
                        "domain": mixed_source.domain,
                        "owner": mixed_source.owner,
                        "paths": [{"relative": "public_html", "purpose": "application"}],
                        "databases": [],
                    },
                }
            ),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        exported = json.loads(result.stdout)
        source_receipt = {
            key: exported[key]
            for key in ("all_native_holds_verified", "retained_services_preserved", "compensation_verified")
        }
        assert source_receipt == {
            "all_native_holds_verified": True,
            "retained_services_preserved": True,
            "compensation_verified": True,
        }
        prepare_native_target(exported, helpers, lab.password, activate=activate_target)
    finally:
        lab.exec("test", "!", "-e", "/etc/apache2/conf-enabled/praho-z-component-" + mixed_source.domain_id + ".conf")
        lab.exec("rm", "-rf", "--", directory)
