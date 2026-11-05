"""Actual PHP-FPM old descriptors must exit; a Unix owner can undo SIGSTOP."""

from __future__ import annotations

import json

import pytest
from fixture_images import fixture_image
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker

NATIVE_PROOF = r'''
import importlib.util,json,os,pwd,signal,subprocess,tempfile,time
from pathlib import Path
from uuid import uuid4
spec=importlib.util.spec_from_file_location('fence','/run/praho-component-fence.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
def run(*args,**kwargs): return subprocess.run(args,check=True,capture_output=True,**kwargs)
def wait_for(predicate):
    for attempt in range(100):
        if predicate(): return
        time.sleep(.05)
    raise AssertionError('Native condition did not converge')
with tempfile.TemporaryDirectory(prefix='praho-site-fence-',dir='/var/lib') as temporary:
    root=Path(temporary); root.chmod(0o755)
    home=root/'home'; web=home/'public_html'; web.mkdir(parents=True)
    run('useradd','--no-create-home','--home-dir',str(home),'sitewriter')
    owner=pwd.getpwnam('sitewriter'); os.chown(home,owner.pw_uid,owner.pw_gid); os.chown(web,owner.pw_uid,owner.pw_gid)
    retained=home/'Maildir'; retained.mkdir(); os.chown(retained,owner.pw_uid,owner.pw_gid)
    outside=retained/'message'; outside.write_text('retained'); os.chown(outside,owner.pw_uid,owner.pw_gid)
    original=outside.stat(); shadow=run('getent','shadow','sitewriter').stdout
    script=web/'fence.php'; marker=web/'old-descriptor'; trigger=home/'continue'
    script.write_text('<?php $mode=$_GET["mode"]??"hold"; $f=@fopen(__DIR__.($mode=="hold"?"/old-descriptor":"/fresh"),"a"); if(!$f){echo "readonly";exit;} fwrite($f,"ready"); fflush($f); if($mode=="hold"){while(!file_exists('+json.dumps(str(trigger))+')){usleep(20000);} fwrite($f,"continued");} fclose($f); echo "writable";')
    script.chmod(0o644)
    private=root/'private-tmp'; private.mkdir()
    config=root/'php-fpm.conf'
    config.write_text('[global]\ndaemonize=no\nerror_log='+str(root/'php.log')+'\n[123456789]\nuser=sitewriter\ngroup=sitewriter\nlisten=127.0.0.1:9070\npm=static\npm.max_children=2\nchdir='+str(home)+'\ncatch_workers_output=yes\n')
    binary=next(Path('/usr/sbin').glob('php-fpm[0-9]*'))
    startup="import os,subprocess,sys; subprocess.run(['mount','--bind',sys.argv[1],'/tmp'],check=True); os.execv(sys.argv[2],[sys.argv[2],'--nodaemonize','--fpm-config',sys.argv[3]])"
    master=subprocess.Popen(['unshare','--mount','--propagation','private','python3','-c',startup,str(private),str(binary),str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    mailer=subprocess.Popen(['runuser','-u','sitewriter','--','python3','-c','import sys,time; f=open(sys.argv[1],"a"); time.sleep(120)',str(outside)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    client=None; fence=None
    def request(mode,background=False):
        env={**os.environ,'SCRIPT_FILENAME':str(script),'SCRIPT_NAME':'/fence.php','REQUEST_METHOD':'GET','QUERY_STRING':'mode='+mode,'SERVER_PROTOCOL':'HTTP/1.1','GATEWAY_INTERFACE':'CGI/1.1','REDIRECT_STATUS':'200','CONTENT_LENGTH':'0'}
        process=subprocess.Popen(['cgi-fcgi','-bind','-connect','127.0.0.1:9070'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if background: return process
        output,error=process.communicate(timeout=10)
        assert process.returncode==0,(output,error)
        return output
    try:
        wait_for(lambda: 'fpm is running' in (root/'php.log').read_text() if (root/'php.log').exists() else False)
        client=request('hold',True); wait_for(marker.exists)
        system=module.FencingSystem(); scope=system.scan(home,('public_html',))
        writers=system.writers(scope,'123456789',owner.pw_uid)
        assert len(writers)==1 and writers[0]['kind']=='php_fpm_pool',writers
        old=writers[0]
        fence=module.PathFence(home,('public_html',),'123456789',owner.pw_uid,str(uuid4()),scope['tree_digest'],state_dir=root/'journal',system=system)
        # Positive control: preserved Unix ownership permits the owner to undo SIGSTOP.
        descriptor=os.pidfd_open(old['pid']); system.assert_writer(old)
        try: signal.pidfd_send_signal(descriptor,signal.SIGSTOP)
        finally: os.close(descriptor)
        wait_for(lambda: system.is_stopped(old))
        try: fence.apply()
        except ValueError as error: assert 'stopped' in str(error),str(error)
        else: raise AssertionError('Pre-existing stopped writer was mutated')
        assert not fence.state_file.exists() and system.is_stopped(old)
        owner_continue="""import os,signal,sys
from pathlib import Path
try: descriptor=os.pidfd_open(int(sys.argv[1]))
except ProcessLookupError: print('exited'); raise SystemExit(0)
try:
 fields=Path('/proc/'+sys.argv[1]+'/stat').read_text().rpartition(')')[2].split()
 if fields[19]==sys.argv[2]: signal.pidfd_send_signal(descriptor,signal.SIGCONT); print('continued')
 else: print('replacement preserved')
except (FileNotFoundError,ProcessLookupError): print('exited')
finally: os.close(descriptor)
"""
        assert run('runuser','-u','sitewriter','--','python3','-c',owner_continue,str(old['pid']),old['start_time']).stdout.strip()==b'continued'
        wait_for(lambda: not system.is_stopped(old))
        topology=system.qualify(home,('public_html',)); assert len(topology['namespaces'])==2,topology
        fence.apply(); fence.verify()
        journal=json.loads(fence.state_file.read_text())
        assert journal['writers'][0]['phase']=='exited',journal
        assert system.exited(old) and not system.writers(system.scan(home,('public_html',)),'123456789',owner.pw_uid)
        assert len(journal['mounts'])==2,journal
        client.communicate(timeout=10)
        # A continuation signal can no longer reopen the killed process's old descriptor.
        run('runuser','-u','sitewriter','--','python3','-c',owner_continue,str(old['pid']),old['start_time'])
        run('runuser','-u','sitewriter','--','touch',str(trigger)); time.sleep(.1)
        assert marker.read_text()=='ready'
        assert b'readonly' in request('fresh')
        assert master.poll() is None and mailer.poll() is None
        run('runuser','-u','sitewriter','--','python3','-c','from pathlib import Path; import sys; Path(sys.argv[1]).write_text("retained still writable")',str(outside))
        assert outside.stat().st_uid==original.st_uid and outside.read_text()=='retained still writable'
        assert run('getent','shadow','sitewriter').stdout==shadow
        fence.verify(); fence.release()
        assert b'writable' in request('fresh')
        assert system.exited(old) and master.poll() is None and mailer.poll() is None
        assert run('getent','shadow','sitewriter').stdout==shadow
        print(json.dumps({'real_php_writer_exited':True,'owner_cont_cannot_revive_old_fd':True,'private_tmp_namespaces':2,'fresh_worker_readonly_then_writable_after_release':True,'retained_service_and_authentication_preserved':True}))
    finally:
        # This entire container is disposable; never restart or touch shared services.
        if client is not None and client.poll() is None: client.kill(); client.wait()
        for process in (master,mailer):
            if process.poll() is None: process.terminate()
        for process in (master,mailer):
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
'''


def build_component_image(version: str) -> str:
    image = fixture_image(f"praho-component-php:{version}")
    built = docker(
        "build", "--build-arg", f"UBUNTU_VERSION={version}", "-t", image,
        "-f", str(ROOT / "tests/deploy/component/Dockerfile"), str(ROOT / "tests/deploy/component"), check=False,
    )
    assert built.returncode == 0, built.stderr[-4000:]
    return image


@pytest.mark.parametrize("version", ["24.04", "26.04"])
def test_native_php_writer_exit_and_private_tmp_compensation(version: str) -> None:
    image = build_component_image(version)
    container = docker(
        "run",
        "--rm",
        "-d",
        "--privileged",
        "--network",
        "none",
        "--entrypoint",
        "/bin/sleep",
        image,
        "300",
    ).stdout.strip()
    try:
        for name in ("praho-component-paths.py", "praho-component-fence.py"):
            source = (ROOT / "services/platform/infrastructure/ansible/playbooks/files" / name).read_text()
            docker("exec", "-i", container, "tee", "/run/" + name, input_text=source)
        result = docker("exec", "-i", container, "python3", "-", input_text=NATIVE_PROOF, check=False)
        assert result.returncode == 0, result.stderr[-6000:]
        assert json.loads(result.stdout) == {
            "real_php_writer_exited": True,
            "owner_cont_cannot_revive_old_fd": True,
            "private_tmp_namespaces": 2,
            "fresh_worker_readonly_then_writable_after_release": True,
            "retained_service_and_authentication_preserved": True,
        }
    finally:
        docker("rm", "-f", container)
