"""Native same-superblock bind aliases bypass a path-only read-only mount fence."""

from __future__ import annotations

import json

import pytest
from test_component_path_fence_docker import build_component_image
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker

NATIVE_PROOF = r'''
import importlib.util,json,os,subprocess,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location("paths","/run/praho-component-mount-qualification.py")
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
def run(*args): subprocess.run(args,check=True,capture_output=True)
def refuses(home, text):
    try: module.qualify_mounts(home,("public_html",))
    except ValueError as error:
        assert text in str(error),str(error)
    else: raise AssertionError("Unsafe mount topology was accepted")
with tempfile.TemporaryDirectory(prefix="praho mount proof-",dir="/var/lib") as temporary:
    home=Path(temporary); web=home/"public_html"; web.mkdir(); data=web/"data"; data.write_text("before")
    alias=home/"retained-service-alias"; alias.mkdir()
    baseline=module.qualify_mounts(home,("public_html",)); assert len(baseline["namespaces"])==1,baseline
    run("mount","--bind",str(web),str(alias))
    try:
        assert module.scan_paths(home,("public_html",))["bytes"]==len("before")
        refuses(home,"alias")
        run("mount","--bind",str(web),str(web))
        try:
            run("mount","-o","remount,bind,ro",str(web))
            (alias/"data").write_text("alias changed the frozen tree")
            assert data.read_text()=="alias changed the frozen tree"
            refuses(home,"alias")
        finally: run("umount",str(web))
    finally: run("umount",str(alias))
    private=home/"private-tmp"; private.mkdir()
    ready=home/"ready"
    child_code="""import subprocess,sys,time
from pathlib import Path
subprocess.run(['mount','--bind',sys.argv[1],'/tmp'],check=True)
if sys.argv[4]=='alias': subprocess.run(['mount','--bind',sys.argv[2],sys.argv[3]],check=True)
Path(sys.argv[5]).write_text('ready')
time.sleep(120)
"""
    def namespace(mode):
        ready.unlink(missing_ok=True)
        child=subprocess.Popen(['unshare','--mount','--propagation','private','python3','-c',child_code,str(private),str(web),str(alias),mode,str(ready)])
        for attempt in range(100):
            if ready.exists(): return child
            assert child.poll() is None,"Private namespace exited"
            time.sleep(.02)
        child.terminate(); child.wait(); raise AssertionError("Private namespace did not start")
    child=namespace('private-tmp')
    try:
        qualified=module.qualify_mounts(home,("public_html",))
        assert len(qualified['namespaces'])==2,qualified
        assert any(item['pid']==child.pid and item['roots']==[str(web)] for item in qualified['namespaces']),qualified
        held_namespace=os.open(f'/proc/{child.pid}/ns/mnt',os.O_RDONLY)
    finally: child.terminate(); child.wait()
    try: refuses(home,'descriptor-held')
    finally: os.close(held_namespace)
    child=namespace('alias')
    try: refuses(home,'alias')
    finally: child.terminate(); child.wait()
    run("mount","--bind",str(web),str(web))
    try:
        run("mount","-o","remount,bind,ro",str(web))
        refuses(home,'mount')
        namespace=module._mount_witness(Path('/proc/self'))[0]
        owned=[item['mount_id'] for item in module._mount_table(Path('/proc/self'),namespace) if item['mountpoint']==str(web)]
        assert len(owned)==1,owned
        verified=module.qualify_mounts(home,("public_html",),owned_mounts={namespace:owned})
        assert any(item['mount_id']==owned[0] and item['read_only'] for item in verified['mounts'])
        try: data.write_text('must fail')
        except OSError: pass
        else: raise AssertionError('Owned read-only fence was writable')
    finally: run('umount',str(web))
    print(json.dumps({'existing_alias_rejected':True,'alias_write_bypass_reproduced':True,'private_tmp_allowed':True,'other_namespace_alias_rejected':True,'exact_owned_readonly_mount_verified':True,'held_namespace_requires_preparation':True}))
'''


@pytest.mark.parametrize("version", ["24.04", "26.04"])
def test_native_bind_alias_and_private_tmp_qualification(version: str) -> None:
    image = build_component_image(version)
    container = docker(
        "run", "--rm", "-d", "--privileged", "--network", "none", "--entrypoint", "/bin/sleep", image, "300"
    ).stdout.strip()
    try:
        source = (
            ROOT / "services/platform/infrastructure/ansible/playbooks/files/praho-component-paths.py"
        ).read_text()
        docker("exec", "-i", container, "tee", "/run/praho-component-mount-qualification.py", input_text=source)
        result = docker("exec", "-i", container, "python3", "-", input_text=NATIVE_PROOF, check=False)
        assert result.returncode == 0, result.stderr[-5000:]
        assert json.loads(result.stdout) == {
            "existing_alias_rejected": True,
            "alias_write_bypass_reproduced": True,
            "private_tmp_allowed": True,
            "other_namespace_alias_rejected": True,
            "exact_owned_readonly_mount_verified": True,
            "held_namespace_requires_preparation": True,
        }
    finally:
        docker("rm", "-f", container)
