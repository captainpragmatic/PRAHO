"""Committed source component cleanup preserves live native mail/DNS/Unix and TLS material."""

# ruff: noqa: S608 -- exact alphanumeric disposable native owner is SQL-qualified before this fixture.

import json
import re
import subprocess
from pathlib import Path

from apps.provisioning.virtualmin_security import connection_identity
from tests.virtualmin_lab.components.conftest import MixedSource
from tests.virtualmin_lab.components.test_source_coordinator import NATIVE_PREPARATION

NATIVE_RETIREMENT = (
    NATIVE_PREPARATION
    + r"""
manifest=module.inspection.inspect_source(request)
assert not manifest['preparation'],manifest['preparation']
# A completed rollback must retire its exact ready native export before a new
# reviewed UUID can replace the domain parent. The old UUID must stay retired
# even after that replacement also compensates and releases its holds.
original=module.NativeSource(request,str(uuid4()),module.authority_digest(manifest))
original.coordinator.apply()
export_spec=importlib.util.spec_from_file_location('source_export',root/'praho-component-source-export.py')
exporter=importlib.util.module_from_spec(export_spec);export_spec.loader.exec_module(exporter)
old_export=exporter.export_source(original)
original.coordinator.release()
replacement=module.NativeSource(request,str(uuid4()),module.authority_digest(module.inspection.inspect_source(request)))
try:replacement.coordinator.apply()
except ValueError as error:assert 'export' in str(error) or 'artifact' in str(error)
else:raise AssertionError('A new source UUID erased private ready-export ownership')
assert original.coordinator.journal.read()['operation_id']==original.operation and Path(old_export['path']).exists()
retire_spec=importlib.util.spec_from_file_location('source_retirement',root/'praho-component-retire.py')
retirement=importlib.util.module_from_spec(retire_spec);retire_spec.loader.exec_module(retirement)
retirement.cleanup_released_export(request,original.operation,original.authority)
replacement.coordinator.apply();replacement.coordinator.release()
retirement.cleanup_released_export(request,replacement.operation,replacement.authority)
try:original.coordinator.apply()
except ValueError as error:assert 'seen' in str(error) or 'history' in str(error)
else:raise AssertionError('A delayed old UUID fenced the source again after its replacement released')
assert original.coordinator._operation_history(original.coordinator.journal.identity).read()['phase']=='retired'
assert not list(Path(old_export['path']).parent.iterdir())
manifest=module.inspection.inspect_source(request)
source=module.NativeSource(request,str(uuid4()),module.authority_digest(manifest))
source.coordinator.apply();source.coordinator.verify()
export_spec=importlib.util.spec_from_file_location('source_export',root/'praho-component-source-export.py')
exporter=importlib.util.module_from_spec(export_spec);export_spec.loader.exec_module(exporter)
exported=exporter.export_source(source)
source.coordinator.commit(archive_sha256=exported['sha256'],target_receipt_sha256='a'*64)
# A legitimate post-commit Unix/mail password rotation must not cause deletion
# to restore archived credentials or compare against the pre-commit auth digest.
rotated='Rotated'+data['password']
changed=subprocess.run(['/usr/sbin/chpasswd'],input=request['owner']+':'+rotated+'\n',text=True,capture_output=True)
assert changed.returncode==0,'Could not rotate the disposable retained mail credential'
identity=retained_probe.unix_identity(request['owner'])
retained_probe.assert_retained_services(request['owner'],request['domain'],rotated,identity)
before=module.inspection._native_domain(request)
certificates={key:(path,hashlib.sha256(Path(path).read_bytes()).hexdigest()) for key,path in before.items()
 if key in {'ssl_cert','ssl_key','ssl_chain','ssl_combined','ssl_everything'} and path}
dns={kind:run(['dig','+short','@127.0.0.1',request['domain'],kind]) for kind in ['SOA','MX','TXT','A','AAAA']}
retire_spec=importlib.util.spec_from_file_location('source_retirement',root/'praho-component-retire.py')
retirement=importlib.util.module_from_spec(retire_spec);retire_spec.loader.exec_module(retirement)
receipt=retirement.retire_source(request,source.operation,source.authority)
assert receipt=={'phase':'retired','operation_id':source.operation,'source_domain_id':request['domain_id']}
assert retirement.retire_source(request,source.operation,source.authority)==receipt
current=module.inspection._fields(Path('/etc/webmin/virtual-server/domains')/request['domain_id'])
assert current['web']=='0' and current['ssl']=='0'
assert current['mail']=='1' and current['dns']=='1' and current['unix']=='1'
assert current['db_mysql']=='' and current['mysql']=='0'
for key,(path,digest) in certificates.items():
 assert current[key]==path and hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest,'Source TLS material changed'
assert not Path(manifest['source']['home'],'public_html').exists()
assert Path(manifest['source']['home'],'Maildir').is_dir()
assert not Path('/etc/apache2/conf-enabled/praho-z-component-'+request['domain_id']+'.conf').exists()
assert not list(Path('/etc/php').glob('*/fpm/pool.d/'+request['domain_id']+'.conf'))
assert sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '"+owner+"'")==[]
assert sql("SELECT User FROM mysql.user WHERE User = '"+owner+"'")==[]
assert not list(Path(exported['path']).parent.iterdir()),'Sensitive source export staging remains'
assert {kind:run(['dig','+short','@127.0.0.1',request['domain'],kind]) for kind in dns}==dns
retained_probe.assert_retained_services(request['owner'],request['domain'],rotated,identity)
for fence in (source.coordinator,source.build(source.coordinator.journal.read()['context'])['web'],
 source.build(source.coordinator.journal.read()['context'])['cron'],source.build(source.coordinator.journal.read()['context'])['database']):
 try:fence.release()
 except ValueError:pass
 else:raise AssertionError('A late source child release was accepted after retirement')
print(json.dumps({'selected_source_components_retired':True,'postcommit_rotated_mail_authentication_preserved':True,
 'native_domain_unix_mail_dns_tls_retained':True,'sensitive_export_artifacts_removed':True,'late_release_refused':True,
 'previous_export_cleanup_required':True,'delayed_old_source_uuid_refused':True}))
"""
)


def test_native_committed_source_retirement_preserves_current_retained_services(mixed_source: MixedSource) -> None:
    lab = mixed_source.lab
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-retire-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-retire-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    installed = [
        *helpers.glob("praho-component-*.py"),
        helpers / "praho-component-retire.pl",
        helpers / "praho-apache-bindings.py",
        helpers / "praho-recovery-credentials.pl",
        helpers / "praho-default-site.conf",
        Path(__file__).with_name("retained_probe.py"),
    ]
    try:
        for path in installed:
            copied = subprocess.run(  # noqa: S603 -- public helper code into the exact owned fixture directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + path.name],  # noqa: S607
                input=path.read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0
        result = subprocess.run(  # noqa: S603 -- owned disposable native domain; private credentials only on stdin
            ["docker", "exec", "-i", lab.node.container, "python3", "-c", NATIVE_RETIREMENT],  # noqa: S607
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
            timeout=300,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert all(json.loads(result.stdout).values())
    finally:
        lab.exec("rm", "-rf", "--", directory)
