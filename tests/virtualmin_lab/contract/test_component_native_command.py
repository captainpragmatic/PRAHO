"""Native target callbacks receive placeholder passwords through private stdin, with real identity preflight."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tests.virtualmin_lab.contract.harness import Lab

NATIVE_PROOF = r"""
import importlib.util,json,secrets,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]);suffix=secrets.token_hex(5)
owner='comp'+suffix;domain='component-native-'+suffix+'.praho.test'
spec=importlib.util.spec_from_file_location('target_preflight',root/'praho-component-target-preflight.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
manifest={'source':{'owner':owner},'databases':[{'name':owner+'_web','principals':[{'user':'app'+suffix}]}]}
absent=module.preflight_target(manifest)
assert absent['sql_users']==sorted([owner,'app'+suffix])
def run(program,arguments):
 result=subprocess.run(['/usr/bin/perl',str(root/'praho-component-native-command.pl')],
  input=json.dumps({'program':program,'arguments':arguments}),capture_output=True,text=True,timeout=180)
 assert result.returncode==0,'The qualified native target callback failed: '+program
 return result.stdout.strip()
identity=None
try:
 arguments=['--domain',domain,'--user',owner,'--pass','Qz9'+secrets.token_hex(16)]
 for feature in ('unix','dir','web','ssl','mysql','logrotate'):arguments.append('--'+feature)
 run('create-domain',arguments)
 identity=run('list-domains',['--domain',domain,'--id-only'])
 assert identity.isdecimal()
 assert run('list-domains',['--domain',domain,'--user-only'])==owner
 native=Path('/etc/webmin/virtual-server/domains')/identity
 fields=dict(line.split('=',1) for line in native.read_text().splitlines() if '=' in line)
 assert fields['id']==identity and fields['dom']==domain and fields['user']==owner
 assert fields.get('mail','0')=='0' and fields.get('dns','0')=='0'
 try:module.preflight_target(manifest)
 except ValueError:pass
 else:raise AssertionError('The freshly created target identity was incorrectly reported absent')
 run('disable-domain',['--domain',domain])
 assert subprocess.check_output(['getent','shadow',owner],text=True).split(':')[1].startswith(('!','*'))
 print(json.dumps({'native_preflight_verified':True,'private_native_creation_verified':True,'native_disable_verified':True}))
finally:
 if identity:
  fields=dict(line.split('=',1) for line in (Path('/etc/webmin/virtual-server/domains')/identity).read_text().splitlines() if '=' in line)
  assert fields['dom']==domain and fields['user']==owner,'Native target identity changed before fixture cleanup'
  run('delete-domain',['--domain',domain])
  assert not (Path('/etc/webmin/virtual-server/domains')/identity).exists(),'Native target deletion is not confirmed'
"""


def test_native_component_target_creation_keeps_arguments_private_and_checks_identity(lab: Lab) -> None:
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-target-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-target-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        for filename in (
            "praho-component-native-command.pl",
            "praho-component-target-preflight.py",
            "praho-component-mysql.py",
        ):
            copied = subprocess.run(  # noqa: S603 -- public helper code into the exact task-owned native directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + filename],  # noqa: S607
                input=(helpers / filename).read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0
        proof = subprocess.run(  # noqa: S603 -- fixed native program wrapper; generated credentials remain on-node
            ["docker", "exec", "-i", lab.node.container, "python3", "-", directory],  # noqa: S607
            input=NATIVE_PROOF,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
        assert proof.returncode == 0, proof.stderr
        assert json.loads(proof.stdout) == {
            "native_preflight_verified": True,
            "private_native_creation_verified": True,
            "native_disable_verified": True,
        }
    finally:
        lab.exec("rm", "-rf", "--", directory)
