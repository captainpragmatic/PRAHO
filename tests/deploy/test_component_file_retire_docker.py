"""A retained Unix owner cannot mutate selected directories through old quarantine FDs."""

from __future__ import annotations

import json

import pytest
from test_component_path_fence_docker import build_component_image
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker

NATIVE_PROOF = r'''
import importlib.util,json,os,pwd,subprocess,tempfile
from pathlib import Path
from uuid import uuid4
spec=importlib.util.spec_from_file_location('retirement','/run/praho-component-file-retire.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
subprocess.run(['useradd','--no-create-home','--shell','/usr/sbin/nologin','retireowner'],check=True)
owner=pwd.getpwnam('retireowner')
shadow=subprocess.run(['getent','shadow','retireowner'],check=True,capture_output=True).stdout
ATTACKER=r"""
import json,os,sys
web=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
nested=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
mail=sys.argv[3]
print('ready',flush=True)
for line in sys.stdin:
 action=line.strip()
 if action=='late':
  descriptor=os.open('foreign-data',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o640,dir_fd=web)
  os.write(descriptor,b'ordinary Unix owner late entry');os.close(descriptor)
  print('inserted',flush=True)
 elif action=='frozen':
  results=[]
  for descriptor in (web,nested):
   try:
    created=os.open('unexpected-write',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=descriptor)
   except PermissionError:results.append('denied')
   else:os.close(created);results.append('writable')
  try:os.rename('index.php','moved.php',src_dir_fd=web,dst_dir_fd=web)
  except PermissionError:results.append('denied')
  else:results.append('renamed')
  with open(mail+'/new-delivery','w') as output:output.write('retained owner remains usable')
  print(json.dumps(results),flush=True)
"""
for scenario in ('retire','late'):
 with tempfile.TemporaryDirectory(prefix='praho-retire-proof-',dir='/var/lib') as temporary:
  base=Path(temporary);base.chmod(0o755)
  home=base/'home';web=home/'public_html';nested=web/'nested';nested.mkdir(parents=True)
  (web/'index.php').write_text('selected application');(nested/'upload').write_text('selected upload')
  mail=home/'Maildir';mail.mkdir();message=mail/'message';message.write_text('retained mail')
  for path in (home,web,nested,web/'index.php',nested/'upload',mail,message):
   os.chown(path,owner.pw_uid,owner.pw_gid)
  home.chmod(0o755);web.chmod(0o755);nested.chmod(0o755);mail.chmod(0o755)
  home_before=(home.stat().st_ino,home.stat().st_uid,home.stat().st_gid,home.stat().st_mode)
  mail_before=(message.stat().st_ino,message.stat().st_uid,message.stat().st_gid,message.stat().st_mode,message.read_bytes())
  attacker=subprocess.Popen(['runuser','-u','retireowner','--','python3','-u','-c',ATTACKER,str(web),str(nested),str(mail)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  assert attacker.stdout.readline().strip()=='ready','Retained Unix owner could not open the selected directory fixture'
  operation=str(uuid4());state=base/'state';quarantine=base/'quarantine'
  receipt=module.capture(home,('public_html',),'123456789',operation,'a'*64,state_dir=state)
  assert module.capture(home,('public_html',),'123456789',operation,'a'*64,state_dir=state)==receipt
  original_delete,original_rename=module.Retirement._delete,module._rename
  probed=[]
  try:
   if scenario=='retire':
    def after_freeze(self,*args,**kwargs):
     if not probed:
      attacker.stdin.write('frozen\n');attacker.stdin.flush()
      assert json.loads(attacker.stdout.readline())==['denied','denied','denied'],'An old owner dirFD still mutated the captured namespace'
      probed.append(True)
     return original_delete(self,*args,**kwargs)
    module.Retirement._delete=after_freeze
    result=module.retire(receipt,state_dir=state,quarantine_dir=quarantine)
    assert result['phase']=='retired' and probed and not web.exists()
    assert (mail/'new-delivery').read_text()=='retained owner remains usable'
    assert module.retire(receipt,state_dir=state,quarantine_dir=quarantine)==result
   else:
    def late_entry(*args,**kwargs):
     result=original_rename(*args,**kwargs)
     attacker.stdin.write('late\n');attacker.stdin.flush()
     assert attacker.stdout.readline().strip()=='inserted','Private quarantine alone unexpectedly fenced an old directory FD'
     return result
    module._rename=late_entry
    try:module.retire(receipt,state_dir=state,quarantine_dir=quarantine)
    except ValueError as error:assert 'closure' in str(error) or 'changed' in str(error)
    else:raise AssertionError('An unapproved late namespace entry was deleted')
    foreign=quarantine/operation/'root-000000/foreign-data'
    assert foreign.read_bytes()==b'ordinary Unix owner late entry'
    assert (foreign.stat().st_uid,foreign.stat().st_mode&0o777)==(owner.pw_uid,0o640)
    assert (quarantine/operation/'root-000000').stat().st_uid==owner.pw_uid,'Metadata changed before complete closure verification'
    try:module.retire(receipt,state_dir=state,quarantine_dir=quarantine)
    except ValueError as error:assert 'interrupted' in str(error)
    else:raise AssertionError('An uncertain quarantine was adopted on retry')
   assert (home.stat().st_ino,home.stat().st_uid,home.stat().st_gid,home.stat().st_mode)==home_before
   assert (message.stat().st_ino,message.stat().st_uid,message.stat().st_gid,message.stat().st_mode,message.read_bytes())==mail_before
   assert subprocess.run(['getent','shadow','retireowner'],check=True,capture_output=True).stdout==shadow
  finally:
   module.Retirement._delete=original_delete;module._rename=original_rename
   attacker.stdin.close();attacker.wait(timeout=10)
   assert attacker.returncode==0,attacker.stderr.read()
print(json.dumps({'captured_tree_removed':True,'old_directory_fds_fenced':True,'late_foreign_entry_preserved':True,'mail_home_and_unix_identity_preserved':True}))
'''


@pytest.mark.parametrize("version", ["24.04", "26.04"])
def test_native_retirement_fences_old_directory_fds_and_preserves_foreign_entries(version: str) -> None:
    image = build_component_image(version)
    container = docker("run", "--rm", "-d", "--network", "none", image).stdout.strip()
    try:
        helpers = ROOT / "services/platform/infrastructure/ansible/playbooks/files"
        for name in ("praho-component-file-retire.py", "praho-component-paths.py", "praho-component-journal.py"):
            docker("exec", "-i", container, "tee", "/run/" + name, input_text=(helpers / name).read_text())
        result = docker("exec", "-i", container, "python3", "-", input_text=NATIVE_PROOF, check=False)
        assert result.returncode == 0, result.stderr[-6000:]
        assert json.loads(result.stdout) == {
            "captured_tree_removed": True,
            "old_directory_fds_fenced": True,
            "late_foreign_entry_preserved": True,
            "mail_home_and_unix_identity_preserved": True,
        }
    finally:
        docker("rm", "-f", container, check=False)
