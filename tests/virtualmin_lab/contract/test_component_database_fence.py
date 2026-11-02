"""Real MariaDB connections prove component fencing preserves an unrelated retained service."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tests.virtualmin_lab.contract.harness import Lab

HELPERS = (
    "praho-component-mysql.py",
    "praho-component-journal.py",
    "praho-component-database-fence.py",
    "praho-component-archive.py",
    "praho-component-database-export.py",
    "praho-component-capacity.py",
    "praho-component-target-database.py",
)

NATIVE_PROOF = r"""
import importlib.util,json,os,secrets,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('database_fence',root/'praho-component-database-fence.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
sql=module.mysql.native_sql
suffix=secrets.token_hex(5)
website,retained='praho_web_'+suffix,'praho_mail_'+suffix
webuser,mailuser='praho_web_'+suffix,'praho_mail_'+suffix
nativeowner='praho_native_'+suffix
password=secrets.token_urlsafe(24)
processes=[]
def login(user,database,query):
 return subprocess.Popen(['mysql','--user',user,'--database',database,'--batch','--skip-column-names'],
  env={**os.environ,'MYSQL_PWD':password},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def sessions(user):
 return sql("SELECT ID FROM information_schema.PROCESSLIST WHERE USER = '"+user+"'")
def wait_for(condition):
 for _ in range(100):
  if condition():return
  time.sleep(.05)
 raise AssertionError('Native SQL condition did not converge')
try:
 for database,user in ((website,webuser),(retained,mailuser)):
  sql(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")
  sql(f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{password}'")
  sql(f"GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'localhost'")
  sql(f"CREATE TABLE `{database}`.fixture (id INT PRIMARY KEY)")
  sql(f"INSERT INTO `{database}`.fixture VALUES(1)")
  process=login(user,database,'SELECT SLEEP(90)')
  process.stdin.write('SELECT SLEEP(90);\n');process.stdin.flush();processes.append(process)
 wait_for(lambda:bool(sessions(webuser)) and bool(sessions(mailuser)))
 before=module.mysql.inspect_databases((website,),(website,))['databases']
 sql(f'CREATE VIEW `{website}`.foreign_definer AS SELECT * FROM `{website}`.fixture')
 assert sql(f"SELECT DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA = '{website}'")==[('root@localhost',)]
 assert module.mysql.inspect_databases((website,),(website,))['preparation'],'Foreign view definer was accepted'
 sql(f'DROP VIEW `{website}`.foreign_definer')
 sql(f'CREATE EVENT `{website}`.foreign_definer ON SCHEDULE EVERY 1 DAY DISABLE DO INSERT INTO `{website}`.fixture VALUES(9)')
 assert sql(f"SELECT STATUS FROM information_schema.EVENTS WHERE EVENT_SCHEMA = '{website}'")==[('DISABLED',)]
 assert module.mysql.inspect_databases((website,),(website,))['preparation'],'Foreign disabled event definer was accepted'
 sql(f'DROP EVENT `{website}`.foreign_definer')
 retained_before=module.mysql.inspect_databases((retained,),(retained,))['databases']
 fence=module.DatabaseFence('123456789',str(uuid4()),before,(website,),state_dir=root/'receipts')
 fence.apply();fence.verify()
 export_spec=importlib.util.spec_from_file_location('database_export',root/'praho-component-database-export.py')
 exports=importlib.util.module_from_spec(export_spec);export_spec.loader.exec_module(exports)
 exported=exports.export_databases(fence,root)
 assert set(exported['dumps'])=={website}
 dump=exported['dumps'][website]
 assert dump.stat().st_mode & 0o777==0o600
 assert b'fixture' in dump.read_bytes() and b'(1)' in dump.read_bytes()
 assert retained.encode() not in dump.read_bytes(),'Retained database entered the website export'
 assert [(row['user'],row['host']) for row in exported['principals']]==[(webuser,'localhost')]
 assert exported['principals'][0]['authentication_string'].startswith('*')
 assert not sessions(webuser) and sessions(mailuser),'Retained SQL session was interrupted'
 processes[0].wait(timeout=5)
 assert processes[1].poll() is None,'Retained SQL connection was terminated'
 denied=login(webuser,website,'INSERT INTO fixture VALUES(2)')
 denied.communicate('INSERT INTO fixture VALUES(2);\n',timeout=10)
 assert denied.returncode != 0,'Locked website principal accepted a new write'
 assert sql(f'SELECT COUNT(*) FROM `{website}`.fixture')==[('1',)]
 assert module.mysql.inspect_databases((retained,),(retained,))['databases']==retained_before
 assert password not in fence.journal.path.read_text()
 fence.release();fence.release()
 restored=login(webuser,website,'INSERT INTO fixture VALUES(2)')
 restored.communicate('INSERT INTO fixture VALUES(2);\n',timeout=10)
 assert restored.returncode == 0,'Compensation did not restore the original application login'
 after=module.mysql.inspect_databases((website,),(website,))['databases']
 assert after[0]['principals']==before[0]['principals'],'Source credentials or grants changed'
 assert sql(f'SELECT COUNT(*) FROM `{website}`.fixture')==[('2',)]
 sql(f"ALTER USER '{webuser}'@'localhost' ACCOUNT LOCK")
 originally_locked=module.mysql.inspect_databases((website,),(website,))['databases']
 second=module.DatabaseFence('123456789',str(uuid4()),originally_locked,(website,),state_dir=root/'receipts')
 second.apply();second.release()
 assert module.mysql.inspect_databases((website,),(website,))['databases'][0]['principals'][0]['locked']
 # Restoration must replace native wildcard grants with exact selected schema
 # patterns. An underscore in a quoted GRANT name is still a wildcard unless escaped.
 foreign=website.replace('_','x',1)
 sql(f'CREATE DATABASE `{foreign}`')
 try:
  sql(f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{webuser}'@'localhost'")
  for privileges,database,grant_option in module.mysql.selected_schema_grants(
    exported['principals'][0]['grants'],webuser,'localhost',(website,)):
   sql(f"GRANT {privileges} ON {module.mysql.exact_schema(database)}.* TO '{webuser}'@'localhost'"+
    (' WITH GRANT OPTION' if grant_option else ''))
  assert sql(f"SELECT COUNT(*) FROM mysql.db WHERE User = '{webuser}' AND '{foreign}' LIKE Db")==[('0',)]
  sql(f"ALTER USER '{webuser}'@'localhost' ACCOUNT UNLOCK")
  assert not module.mysql.inspect_databases((website,),(website,))['preparation'],'Restored exact grants are not qualified'
  selected_login=login(webuser,website,'SELECT COUNT(*) FROM fixture')
  selected_output,_=selected_login.communicate('SELECT COUNT(*) FROM fixture;\n',timeout=10)
  assert selected_login.returncode==0 and selected_output.strip()=='2'
  foreign_login=login(webuser,foreign,'SELECT 1')
  foreign_login.communicate('SELECT 1;\n',timeout=10)
  assert foreign_login.returncode!=0,'Exact selected schema grants widened into a future unrelated schema'
 finally:
  sql(f'DROP DATABASE `{foreign}`')
 # Restore an independent application login into a separately proven fresh
 # native owner namespace. This exercises real CREATE/ALTER/GRANT behavior,
 # not only the native owner's already-existing SQL account.
 sql(f"DROP USER '{webuser}'@'localhost'")
 sql(f"CREATE USER '{nativeowner}'@'localhost' IDENTIFIED BY '{password}' ACCOUNT LOCK")
 target_spec=importlib.util.spec_from_file_location('target_database',root/'praho-component-target-database.py')
 target_module=importlib.util.module_from_spec(target_spec);target_spec.loader.exec_module(target_module)
 target=target_module.TargetDatabase({'source':{'owner':nativeowner},'databases':before},
  exported['principals'],('localhost',),'123456789',str(uuid4()),'a'*64,state_dir=root/'target-receipts')
 target.apply();target.apply();target.verify()
 held_login=login(webuser,website,'SELECT COUNT(*) FROM fixture')
 held_login.communicate('SELECT COUNT(*) FROM fixture;\n',timeout=10)
 assert held_login.returncode!=0,'A newly restored application principal was not held'
 target.activate();target.activate();target.verify(active=True)
 restored_login=login(webuser,website,'SELECT COUNT(*) FROM fixture')
 restored_output,_=restored_login.communicate('SELECT COUNT(*) FROM fixture;\n',timeout=10)
 assert restored_login.returncode==0 and restored_output.strip()=='2'
 assert target_module.mysql._authentication(sql,nativeowner,'localhost',True)[2] in {'true','1','Y'}
 sql(f'DROP DATABASE `{website}`')
 sql(f"DROP USER '{nativeowner}'@'localhost'")
 target.retire();target.retire()
 assert sql(f"SELECT User FROM mysql.user WHERE User IN ('{nativeowner}','{webuser}')")==[]
 print(json.dumps({'old_website_session_closed':True,'new_website_writes_denied':True,
  'retained_session_and_grants_preserved':True,'compensation_restores_website_login':True,
  'original_credentials_preserved':True,'original_lock_preserved':True,
  'foreign_view_and_disabled_event_definers_refused':True,'selected_private_dump_and_credentials_verified':True,
  'restored_schema_grants_cannot_widen_into_unrelated_databases':True,
  'independent_target_application_account_created_held_and_activated':True,
  'only_receipted_application_principals_removed_after_schema_absence':True}))
finally:
 for process in processes:
  if process.poll() is None:process.terminate()
 for database,user in ((website,webuser),(retained,mailuser)):
  for row in sessions(user):
   assert len(row)==1 and row[0].isdecimal()
   sql('KILL CONNECTION '+row[0])
  sql(f"DROP USER IF EXISTS '{user}'@'localhost'")
  sql(f"DROP DATABASE IF EXISTS `{database}`")
 sql(f"DROP USER IF EXISTS '{nativeowner}'@'localhost'")
 for process in processes:
  process.communicate(timeout=5)
"""


def test_native_sql_fence_preserves_retained_sessions_and_original_authentication(lab: Lab) -> None:
    directory = lab.exec("mktemp", "-d", "/var/lib/praho-sql-contract.XXXXXXXX").strip()
    assert re.fullmatch(r"/var/lib/praho-sql-contract\.[A-Za-z0-9]+", directory)
    helpers = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks/files"
    try:
        for filename in HELPERS:
            result = subprocess.run(  # noqa: S603 -- validated disposable lab directory, public helper over stdin
                ["docker", "exec", "-i", lab.node.container, "tee", directory + "/" + filename],  # noqa: S607
                input=(helpers / filename).read_text(),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert result.returncode == 0, "Could not transfer the native SQL helper to the disposable lab"
        proof = subprocess.run(  # noqa: S603 -- fixed Python entrypoint in the disposable lab; no shell
            ["docker", "exec", "-i", lab.node.container, "python3", "-", directory],  # noqa: S607
            input=NATIVE_PROOF,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        assert proof.returncode == 0, proof.stderr
        assert json.loads(proof.stdout) == {
            "old_website_session_closed": True,
            "new_website_writes_denied": True,
            "retained_session_and_grants_preserved": True,
            "compensation_restores_website_login": True,
            "original_credentials_preserved": True,
            "original_lock_preserved": True,
            "foreign_view_and_disabled_event_definers_refused": True,
            "selected_private_dump_and_credentials_verified": True,
            "restored_schema_grants_cannot_widen_into_unrelated_databases": True,
            "independent_target_application_account_created_held_and_activated": True,
            "only_receipted_application_principals_removed_after_schema_absence": True,
        }
    finally:
        lab.exec("rm", "-rf", "--", directory)
