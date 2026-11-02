"""A fresh full vendor image can create native mail/DNS domains without manual runtime repairs."""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

NATIVE_PROOF = r"""
import http.client,json,os,secrets,ssl,sys,urllib.parse
from pathlib import Path
sys.path.insert(0,'/run/praho-image-proof');import retained_probe
hostname='vm-image-proof.praho.test'
root_password=Path('/etc/lab-node/inject/root_password').read_text().strip()
suffix=secrets.token_hex(5);domain='image-contract-'+suffix+'.praho.test';owner='img'+suffix
password='Qz9'+secrets.token_hex(12)
context=ssl.create_default_context(cafile='/etc/webmin/miniserv.pem')
def api(program,parameters):
 import base64
 connection=http.client.HTTPSConnection(hostname,10000,context=context,timeout=180)
 body=urllib.parse.urlencode({'program':program,'json':'1',**parameters})
 credential=base64.b64encode(('root:'+root_password).encode()).decode()
 try:
  connection.request('POST','/virtual-server/remote.cgi',body,
   {'Authorization':'Basic '+credential,'Content-Type':'application/x-www-form-urlencoded'})
  response=connection.getresponse();value=json.loads(response.read())
  assert response.status==200 and value.get('status')=='success','Fresh native API callback failed'
 finally:connection.close()
created=False
try:
 api('create-domain',{'domain':domain,'user':owner,'pass':password,
  'unix':'','dir':'','web':'','ssl':'','logrotate':'','mysql':'','mail':'','dns':''})
 created=True
 identity=retained_probe.unix_identity(owner)
 retained_probe.assert_retained_services(owner,domain,password,identity)
 assert Path('/etc/usermin/miniserv.pem').read_bytes()==Path('/etc/webmin/miniserv.pem').read_bytes()
 assert os.stat('/etc/usermin/miniserv.pem').st_mode & 0o777 == 0o600
 print(json.dumps({'fresh_native_domain_created':True,'smtp_imap_dns_verified':True,'per_container_tls_verified':True}))
finally:
 if created:api('delete-domain',{'domain':domain})
"""


def docker(*arguments: str, data: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed Docker command and exact newly created disposable container ID
        ["docker", *arguments],  # noqa: S607 -- Docker is the installed lab runtime, resolved through PATH
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def test_fresh_mixed_source_image_has_working_native_mail_dns_and_private_identity() -> None:
    container = ""
    root = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="praho-source-image-", dir=root) as temporary:
        inject = Path(temporary)
        password = inject / "root_password"
        password.write_text(secrets.token_urlsafe(32) + "\n")
        password.chmod(0o600)
        created = docker(
            "run",
            "--detach",
            "--hostname",
            "vm-image-proof.praho.test",
            "--privileged",
            "--cgroupns",
            "host",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--stop-signal",
            "SIGRTMIN+3",
            "--mount",
            "type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup",
            "--mount",
            "type=bind,source=" + str(inject) + ",target=/etc/lab-node/inject,readonly",
            "praho-virtualmin-lab-mixed-source:8.3.0",
            timeout=60,
        )
        assert created.returncode == 0, "Could not start the fresh disposable source image"
        container = created.stdout.strip()
        assert re.fullmatch(r"[0-9a-f]{64}", container)
        try:
            deadline = time.monotonic() + 300
            while True:
                health = docker("inspect", "--format", "{{.State.Health.Status}}", container)
                assert health.returncode == 0, "Fresh source image vanished during first boot"
                if health.stdout.strip() == "healthy":
                    break
                assert time.monotonic() < deadline, (
                    "Fresh source image did not complete native first-boot configuration"
                )
                time.sleep(2)
            assert docker("exec", container, "mkdir", "-m", "700", "/run/praho-image-proof").returncode == 0
            helper = docker(
                "exec",
                "-i",
                container,
                "tee",
                "/run/praho-image-proof/retained_probe.py",
                data=Path(__file__).with_name("retained_probe.py").read_text(),
            )
            assert helper.returncode == 0
            proof = docker("exec", "-i", container, "python3", "-c", NATIVE_PROOF, timeout=240)
            assert proof.returncode == 0, proof.stderr
            assert json.loads(proof.stdout) == {
                "fresh_native_domain_created": True,
                "smtp_imap_dns_verified": True,
                "per_container_tls_verified": True,
            }
        finally:
            assert docker("stop", "--time", "15", container, timeout=30).returncode == 0
            assert docker("rm", container).returncode == 0
