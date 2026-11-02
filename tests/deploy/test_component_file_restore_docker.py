"""Native restore ownership must not make source root-only files readable by the customer."""

from __future__ import annotations

import json

import pytest
from test_component_path_fence_docker import build_component_image
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker

NATIVE_PROOF = r"""
import importlib.util,json,os,pwd,subprocess,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('repair','/run/praho-component-file-restore.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
subprocess.run(['useradd','--no-create-home','--shell','/usr/sbin/nologin','componenttarget'],check=True)
owner=pwd.getpwnam('componenttarget')
with tempfile.TemporaryDirectory(prefix='praho-component-restore-',dir='/var/lib') as directory:
 home=Path(directory)/'home';web=home/'public_html';web.mkdir(parents=True)
 Path(directory).chmod(0o755);home.chmod(0o755);web.chmod(0o755)
 secret=web/'root-private';secret.write_text('source root-only content');secret.chmod(0o600)
 index=web/'index.php';index.write_text('selected website');index.chmod(0o640)
 link=web/'index-link';link.symlink_to('index.php')
 mail=home/'Maildir';mail.mkdir();message=mail/'message';message.write_text('retained')
 # Reproduce native restore_dir's recursive customer chown before repairing its metadata.
 for path in (home,web,secret,index,link):os.chown(path,owner.pw_uid,owner.pw_gid,follow_symlinks=False)
 mail_before=(message.stat().st_uid,message.stat().st_gid,message.stat().st_mode,message.read_bytes())
 denied=['runuser','-u','componenttarget','--','cat',str(secret)]
 assert subprocess.run(denied,capture_output=True).returncode==0,'Bug fixture was not customer-readable'
 records=[
  {'relative':'public_html','uid':1200,'gid':1200,'mode':0o755,'kind':'directory','target':''},
  {'relative':'public_html/root-private','uid':0,'gid':0,'mode':0o600,'kind':'file','target':''},
  {'relative':'public_html/index.php','uid':1200,'gid':1200,'mode':0o640,'kind':'file','target':''},
  {'relative':'public_html/index-link','uid':1200,'gid':1200,'mode':0o777,'kind':'symlink','target':'public_html/index.php'},
 ]
 metadata={'source_uid':1200,'source_gid':1200,'files':records,
  'manifest':{'source':{'home':str(home)},'paths':[{'relative':'public_html'}]}}
 module.repair_component_files(home,metadata,owner.pw_uid,owner.pw_gid)
 module.repair_component_files(home,metadata,owner.pw_uid,owner.pw_gid)
 assert (secret.stat().st_uid,secret.stat().st_gid,secret.stat().st_mode & 0o777)==(0,0,0o600)
 assert subprocess.run(denied,capture_output=True).returncode!=0,'Customer can read the source root-only file'
 assert (index.stat().st_uid,index.stat().st_gid,index.stat().st_mode & 0o777)==(owner.pw_uid,owner.pw_gid,0o640)
 assert (message.stat().st_uid,message.stat().st_gid,message.stat().st_mode,message.read_bytes())==mail_before
 # A changed symlink parent must never redirect root repair into retained mail data.
 index.unlink();link.unlink();secret.unlink();web.rmdir();web.symlink_to(mail,target_is_directory=True)
 try:module.repair_component_files(home,metadata,owner.pw_uid,owner.pw_gid)
 except (ValueError,OSError):pass
 else:raise AssertionError('Changed selected directory was followed into retained data')
 assert (message.stat().st_uid,message.stat().st_gid,message.stat().st_mode,message.read_bytes())==mail_before
 print(json.dumps({'root_only_preserved':True,'customer_mapping_preserved':True,'retained_untouched':True,'changed_parent_refused':True}))
"""


@pytest.mark.parametrize("version", ["24.04", "26.04"])
def test_component_restore_preserves_root_only_permissions_and_rejects_changed_parents(version: str) -> None:
    image = build_component_image(version)
    container = docker("run", "--rm", "-d", "--network", "none", image).stdout.strip()
    try:
        helper = ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-component-file-restore.py"
        docker("exec", "-i", container, "tee", "/run/" + helper.name, input_text=helper.read_text())
        result = docker("exec", "-i", container, "python3", "-", input_text=NATIVE_PROOF, check=False)
        assert result.returncode == 0, result.stderr[-6000:]
        assert json.loads(result.stdout) == {
            "root_only_preserved": True,
            "customer_mapping_preserved": True,
            "retained_untouched": True,
            "changed_parent_refused": True,
        }
    finally:
        docker("rm", "-f", container, check=False)
