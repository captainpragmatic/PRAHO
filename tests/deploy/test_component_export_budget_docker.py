"""Native selected export writers must stop before consuming retained-service capacity."""

import json

import pytest
from test_component_path_fence_docker import build_component_image
from test_ssh_hardening_docker import ROOT, docker

pytestmark = pytest.mark.docker

NATIVE_PROOF = r"""
import importlib.util,json,os,shutil,subprocess,sys,time
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('exporter','/run/praho-component-database-export.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=Path('/workspace');mail=root/'retained-mail';mail.write_bytes(b'retained original message')
reserve=2*1024*1024
budget=module.capacity.OutputBudget(64*1024*1024,(root,),reserve_bytes=reserve)
processes=[];popen=subprocess.Popen
def expanding(_arguments,**kwargs):
 process=popen([sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'x'*(64*1024*1024))"],**kwargs)
 processes.append(process);return process
path=root/'selected.sql'
with path.open('xb') as stream,patch.object(module.subprocess,'Popen',side_effect=expanding):
 try:module.native_dump('selected_web',budget.writer(stream))
 except ValueError as error:assert 'reserve' in str(error),str(error)
 else:raise AssertionError('An expanding selected dump exhausted the retained filesystem')
assert processes[0].poll() is not None,'The overflowing native dump was left running'
assert shutil.disk_usage(root).free>=reserve,'The migration consumed retained-service reserve'
assert 0<path.stat().st_size<8*1024*1024-reserve
assert mail.read_bytes()==b'retained original message'
(root/'new-mail-delivery').write_bytes(b'retained filesystem remains usable')
# The actual Linux hard file ceiling also covers native backup and sanitizer
# output files in an isolated process; no shared daemon limit is changed.
output=Path('/var/lib/bounded-native-output')
try:module.capacity.run_limited([sys.executable,'-c',"from pathlib import Path;Path('/var/lib/bounded-native-output').write_bytes(b'x'*1048576)"],paths=(Path('/var/lib'),),file_limit=4096)
except ValueError:pass
else:raise AssertionError('A native working-copy writer ignored RLIMIT_FSIZE')
assert output.stat().st_size<=4096
output.unlink()
result=module.capacity.run_limited([sys.executable,'-c',"print('valid selected export')"],paths=(Path('/var/lib'),),file_limit=4096)
assert result.strip()=='valid selected export'
started=time.monotonic()
try:module.capacity.run_limited([sys.executable,'-c','import os,time;child=os.fork();os._exit(0) if child else time.sleep(60)'],paths=(Path('/var/lib'),),file_limit=4096,timeout=.2)
except TimeoutError:pass
else:raise AssertionError('A descendant with inherited output pipes bypassed the deadline')
assert time.monotonic()-started<3,'Timed-out child descendants blocked source cleanup'
print(json.dumps({'expanding_dump_stopped':True,'retained_reserve_preserved':True,'mail_untouched':True,
 'native_file_ceiling_enforced':True,'valid_child_output_accepted':True,'descendant_timeout_bounded':True}))
"""


@pytest.mark.parametrize("version", ["24.04", "26.04"])
def test_native_output_caps_preserve_retained_reserve_and_terminate_descendants(version: str) -> None:
    image = build_component_image(version)
    container = docker(
        "run", "--rm", "-d", "--network", "none", "--tmpfs", "/workspace:rw,size=8m", image
    ).stdout.strip()
    try:
        helpers = ROOT / "services/platform/infrastructure/ansible/playbooks/files"
        for path in helpers.glob("praho-component-*.py"):
            docker("exec", "-i", container, "tee", "/run/" + path.name, input_text=path.read_text())
        result = docker("exec", "-i", container, "python3", "-", input_text=NATIVE_PROOF, check=False)
        assert result.returncode == 0, result.stderr[-6000:]
        assert json.loads(result.stdout) == dict.fromkeys(
            (
                "expanding_dump_stopped",
                "retained_reserve_preserved",
                "mail_untouched",
                "native_file_ceiling_enforced",
                "valid_child_output_accepted",
                "descendant_timeout_bounded",
            ),
            True,
        )
    finally:
        docker("rm", "-f", container, check=False)
