"""Real cron execution, SMTP delivery, IMAP reads and DNS survive the selected-job fence."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tests.virtualmin_lab.components.conftest import MixedSource

NATIVE_PROOF = r"""
import hashlib,imaplib,importlib.util,json,os,pwd,smtplib,ssl,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
data=json.load(sys.stdin);owner=data['owner'];domain=data['domain'];domain_id=data['domain_id']
root=Path(data['directory']);spec=importlib.util.spec_from_file_location('cron_fence',root/'praho-component-cron-fence.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert subprocess.check_output(['systemctl','is-active','cron.service']).strip()==b'active'
assert subprocess.check_output(['virtualmin','list-domains','--domain',domain,'--id-only']).decode().strip()==domain_id
native=pwd.getpwnam(owner);home=Path(native.pw_dir)
assert str(home)=='/home/'+owner
shadow=hashlib.sha256(subprocess.check_output(['getent','shadow',owner])).hexdigest()
selected=home/'public_html/cron-selected';retained=home/'cron-retained'
website=Path('/etc/cron.d')/('praho-component-'+domain_id)
unrelated=Path('/etc/cron.d')/('praho-retained-contract-'+domain_id)
assert not website.exists() and not unrelated.exists()
line='* * * * * /usr/bin/touch '+str(selected)
original='* * * * * '+owner+' /usr/bin/touch '+str(selected)+'\n'
other='* * * * * '+owner+' /usr/bin/touch '+str(retained)+'\n'
fence=module.CronFileFence(domain_id,str(uuid4()),owner,(hashlib.sha256(line.encode()).hexdigest(),),state_dir=root/'receipts')
def wait_for(condition,seconds=85):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  if condition():return
  time.sleep(.2)
 raise AssertionError('Native cron did not reach the expected observable state')
def mail_and_dns():
 token='praho-component-'+uuid4().hex
 client=imaplib.IMAP4_SSL('127.0.0.1',993,ssl_context=ssl._create_unverified_context())
 client.login(owner,data['password'])
 with smtplib.SMTP('127.0.0.1',25,timeout=10) as smtp:
  assert smtp.sendmail('fixture@'+domain,owner+'@'+domain,'From: fixture@'+domain+'\r\nTo: '+owner+'@'+domain+'\r\nSubject: '+token+'\r\n\r\nRetained component fixture.\r\n')=={}
 def delivered():
  assert client.select('INBOX')[0]=='OK'
  status,found=client.search(None,'SUBJECT',token);assert status=='OK'
  return bool(found[0])
 wait_for(delivered,15)
 status,found=client.search(None,'SUBJECT',token);assert status=='OK'
 status,body=client.fetch(found[0].split()[-1],'(RFC822)');assert status=='OK'
 assert any(isinstance(item,tuple) and b'Retained component fixture.' in item[1] for item in body)
 client.logout()
 for kind in ('SOA','MX','A'):
  assert subprocess.check_output(['dig','@127.0.0.1','+short',domain,kind]).strip()
 assert hashlib.sha256(subprocess.check_output(['getent','shadow',owner])).hexdigest()==shadow
try:
 mail_and_dns()
 website.write_text(original);website.chmod(0o644)
 unrelated.write_text(other);unrelated.chmod(0o644)
 wait_for(lambda:selected.exists() and retained.exists())
 fence.apply();fence.verify()
 before=selected.stat().st_mtime_ns;retained_before=retained.stat().st_mtime_ns
 mail_and_dns()
 wait_for(lambda:retained.stat().st_mtime_ns>retained_before)
 assert selected.stat().st_mtime_ns==before,'The selected source job still executes while held'
 assert unrelated.read_text()==other,'A retained job was rewritten'
 assert fence.selected_cron()==(line,),'The target would receive the wrong original job'
 fence.release();fence.release()
 assert website.read_text()==original
 wait_for(lambda:selected.stat().st_mtime_ns>before)
 mail_and_dns()
 print(json.dumps({'selected_job_stops':True,'retained_job_runs':True,'selected_job_compensates':True,
  'mail_receive_and_read_preserved':True,'dns_preserved':True,'unix_authentication_preserved':True}))
finally:
 if fence.journal.path.exists():fence.release()
 for path in (website,unrelated):path.unlink(missing_ok=True)
 for path in (selected,retained):path.unlink(missing_ok=True)
"""


def test_selected_cron_fence_preserves_mail_dns_and_other_jobs(mixed_source: MixedSource) -> None:
    lab = mixed_source.lab
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-component-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-component-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        for name in ("praho-component-journal.py", "praho-component-cron-fence.py"):
            copied = subprocess.run(  # noqa: S603 -- public code over stdin into an exact disposable fixture directory
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + name],  # noqa: S607
                input=(helpers / name).read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert copied.returncode == 0, "Could not install the component cron helper in the fixture"
        payload = {
            "domain": mixed_source.domain,
            "owner": mixed_source.owner,
            "domain_id": mixed_source.domain_id,
            "password": lab.password,
            "directory": directory,
        }
        result = subprocess.run(  # noqa: S603 -- local disposable source; private test password through stdin only
            ["docker", "exec", "-i", lab.node.container, "python3", "-c", NATIVE_PROOF],  # noqa: S607
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=280,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {
            "selected_job_stops": True,
            "retained_job_runs": True,
            "selected_job_compensates": True,
            "mail_receive_and_read_preserved": True,
            "dns_preserved": True,
            "unix_authentication_preserved": True,
        }
    finally:
        lab.exec("rm", "-rf", "--", directory)
