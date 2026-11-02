"""Read-only native vhost evidence for exact disposable component fixtures."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from time import monotonic
from uuid import uuid4

INSPECTION_ERROR_OBSERVATION = r"""
import json as _inspection_json,sys as _inspection_sys,time as _inspection_time
def _inspection_error(kind,value,trace):
 current=trace
 try:
  while current is not None:
   frame=current.tb_frame
   if (frame.f_code.co_name=='_related_domains' and
       frame.f_code.co_filename.endswith('/praho-component-inspect.py')):
    entry=frame.f_locals.get('path');index=frame.f_locals.get('count')
    name=getattr(entry,'name',None)
    if isinstance(name,str) and type(index) is int:
     print('PRAHO_INSPECTION_REFUSAL='+_inspection_json.dumps(
      {'entry':name[:255],'index':index,'time_ns':_inspection_time.time_ns()},
      ensure_ascii=True,separators=(',',':')),file=_inspection_sys.stderr,flush=True)
    break
   current=current.tb_next
 except Exception:
  pass
 _inspection_sys.__excepthook__(kind,value,trace)
_inspection_sys.excepthook=_inspection_error
"""

_WATCH = r"""
import difflib,hashlib,json,os,select,stat,sys,time
from pathlib import Path
site=Path('/etc/apache2/sites-available')/(sys.argv[1]+'.conf')
limit=512*1024;written=0;previous=None;last_digest=None
def emit(value):
 global written
 value['time_ns']=time.time_ns()
 line=json.dumps(value,separators=(',',':'),ensure_ascii=True)+'\n'
 size=len(line.encode())
 if written+size<=limit:
  print(line,end='',flush=True);written+=size
def open_writers():
 found=[]
 for process in Path('/proc').iterdir():
  if not process.name.isdecimal():continue
  try:
   for descriptor in (process/'fd').iterdir():
    try:target=os.readlink(descriptor)
    except OSError:continue
    if target.startswith(str(site)):
     found.append({'pid':int(process.name),'comm':(process/'comm').read_text().strip()})
     break
  except OSError:continue
  if len(found)==16:break
 return found
started=time.monotonic()
emit({'event':'started','pid':os.getpid(),'domain':sys.argv[1]})
while time.monotonic()-started<1800:
 # The controller owns stdin. EOF ends the observer without a remote kill or
 # a persistent native file, including when Docker closes its input stream.
 readable,_,_=select.select([sys.stdin],[],[],0.05)
 if readable and not os.read(sys.stdin.fileno(),1):break
 try:
  descriptor=os.open(site,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(descriptor,'rb') as stream:
   metadata=os.fstat(stream.fileno())
   if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=0 or metadata.st_size>256*1024:
    emit({'event':'unqualified_site'});break
   content=stream.read(256*1024+1)
  if len(content)>256*1024:emit({'event':'oversized_site'});break
 except FileNotFoundError:
  if previous is not None:
   emit({'event':'absent','elapsed':time.monotonic()-started})
   previous=None;last_digest=None
  continue
 except OSError as error:
  emit({'event':'unreadable_site','errno':error.errno});continue
 digest=hashlib.sha256(content).hexdigest()
 if digest==last_digest:continue
 text=content.decode('utf-8',errors='replace')
 delta=''.join(difflib.unified_diff((previous or '').splitlines(True),text.splitlines(True)))[:16384]
 emit({'event':'changed','elapsed':time.monotonic()-started,'sha256':digest,
       'inode':metadata.st_ino,'mtime_ns':metadata.st_mtime_ns,'diff':delta,'open_site_fds':open_writers()})
 previous=text;last_digest=digest
emit({'event':'stopped','elapsed':time.monotonic()-started})
"""


def _stop_observer(process: subprocess.Popen[str], artifact: Path, *, timeout: float = 10) -> None:
    assert process.stdin is not None
    process.stdin.close()
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=max(timeout, 1.0))
        raise
    if code != 0:
        raise RuntimeError(f"Native site observer exited {code}; evidence: {artifact}")


@contextmanager
def observe_target_site(domain: str) -> Iterator[Path]:
    """Observe only the generated public vhost; no native state or credentials are read."""
    if re.fullmatch(r"component-contract-[0-9a-f]{10}\.praho\.test", domain) is None:
        raise ValueError("Native observation requires an exact disposable component fixture")
    directory = Path("output/virtualmin-lab/components")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifact = directory / (uuid4().hex + ".jsonl")
    with artifact.open("x", encoding="utf-8") as output:
        artifact.chmod(0o600)
        process = subprocess.Popen(  # noqa: S603 -- fixed owned lab, read-only script and validated fixture name
            ["docker", "exec", "-i", "vmlab-b", "python3", "-u", "-c", _WATCH, domain],  # noqa: S607
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=output,
            text=True,
        )
        original_error: BaseException | None = None
        try:
            deadline = monotonic() + 10
            while '"event":"started"' not in artifact.read_text():
                if process.poll() is not None or monotonic() >= deadline:
                    raise RuntimeError(f"Native site observer did not start; evidence: {artifact}")
                Event().wait(0.05)
            yield artifact
        except BaseException as error:
            original_error = error
            raise
        finally:
            try:
                _stop_observer(process, artifact)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                if original_error is None:
                    raise
                original_error.add_note(str(error))
