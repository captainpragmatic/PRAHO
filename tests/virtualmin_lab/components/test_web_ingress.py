"""Real HTTP/HTTPS maintenance leaves source mail, DNS, authentication and native backup vhosts unchanged."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tests.virtualmin_lab.components.conftest import MixedSource

NATIVE_PROOF = r"""
import hashlib,importlib.util,json,subprocess,sys,tarfile
from pathlib import Path
from uuid import uuid4
data=json.load(sys.stdin);root=Path(data['directory']);sys.path.insert(0,str(root))
import retained_probe
spec=importlib.util.spec_from_file_location('web_fence',root/'praho-component-web-fence.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
site=Path('/etc/apache2/sites-available')/(data['domain']+'.conf')
original=site.read_bytes();identity=retained_probe.unix_identity(data['owner'])
fence=module.WebIngressFence(data['domain_id'],str(uuid4()),data['domain'],(data['domain'],'www.'+data['domain']),
 hashlib.sha256(original).hexdigest(),state_dir=root/'receipts')
try:
 retained_probe.assert_retained_services(data['owner'],data['domain'],data['password'],identity)
 fence.apply();fence.verify();fence.apply()
 assert site.read_bytes()==original,'Native backup_web would export maintenance instead of the original website'
 assert fence.path.exists()
 assert b'mail.'+data['domain'].encode() not in fence.path.read_bytes(),'Retained service hostname entered the website hold'
 archive=root/'native-while-held.tar.gz'
 backup=['virtualmin','backup-domain','--domain',data['domain'],'--dest',str(archive),
  '--no-differential','--compression','gzip','--include','public_html','--option','dir','dirnologs','1']
 for feature in ('virtualmin','unix','dir','web','ssl','logrotate'):backup.extend(['--feature',feature])
 completed=subprocess.run(backup,capture_output=True,text=True,timeout=120)
 assert completed.returncode==0,'Native selected backup did not complete under the ingress hold'
 with tarfile.open(archive) as bundle:
  native_vhosts=[bundle.extractfile(member).read() for member in bundle
   if member.name.removeprefix('./') in {data['domain']+'_web',data['domain']+'_ssl'}]
 assert len(native_vhosts)==2,'Native HTTP/HTTPS backup callback metadata is missing'
 assert all(b'X-PRAHO-Component-Hold' not in content and b'RedirectMatch 503' not in content for content in native_vhosts), 'Native backup selected the temporary maintenance vhost'
 retained_probe.assert_retained_services(data['owner'],data['domain'],data['password'],identity)
 fence.release();fence.release()
 assert not fence.path.exists() and site.read_bytes()==original
 retained_probe.assert_retained_services(data['owner'],data['domain'],data['password'],identity)
 print(json.dumps({'http_and_https_held':True,'native_backup_inputs_unchanged':True,
  'retained_mail_dns_authentication_preserved':True,'exact_owned_compensation_verified':True}))
finally:
 if fence.journal.path.exists():fence.release()
"""


def test_native_website_ingress_hold_and_compensation_preserve_retained_services(mixed_source: MixedSource) -> None:
    lab = mixed_source.lab
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-ingress-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-ingress-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    files = [
        helpers / name
        for name in ("praho-component-journal.py", "praho-apache-bindings.py", "praho-component-web-fence.py")
    ]
    files.append(Path(__file__).with_name("retained_probe.py"))
    try:
        for source in files:
            copied = subprocess.run(  # noqa: S603 -- public helper into exact fixture-owned temporary directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + source.name],  # noqa: S607
                input=source.read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0, "Could not install the native component ingress helper"
        result = subprocess.run(  # noqa: S603 -- local disposable source; private password sent only through stdin
            ["docker", "exec", "-i", lab.node.container, "python3", "-c", NATIVE_PROOF],  # noqa: S607
            input=json.dumps(
                {
                    "domain": mixed_source.domain,
                    "owner": mixed_source.owner,
                    "domain_id": mixed_source.domain_id,
                    "password": lab.password,
                    "directory": directory,
                }
            ),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {
            "http_and_https_held": True,
            "native_backup_inputs_unchanged": True,
            "retained_mail_dns_authentication_preserved": True,
            "exact_owned_compensation_verified": True,
        }
    finally:
        lab.exec("test", "!", "-e", "/etc/apache2/conf-enabled/praho-z-component-" + mixed_source.domain_id + ".conf")
        lab.exec("rm", "-rf", "--", directory)
