"""Run praho-quota-metadata.pl inside a lab node the way the quota coordinator does (#776, 7A.1 in plan 7A.4).

Usage inside the node, as root: python3 quota_metadata_driver.py apply|restore <metadata.pl>, the child's JSON
payload on stdin. It writes the running receipt the child checks (phase, token, generation, request digest), opens
the lane descriptor the child inherits and locks, and prints the child's exit code and output as one JSON line.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys


def main() -> None:
    mode, script = sys.argv[1], sys.argv[2]
    payload = json.loads(sys.stdin.read())
    request = payload["request"] if mode == "restore" else payload
    identity = request["identity"]
    scope = f"/var/lib/praho/quotas/{identity['installation']}/{identity['domain_id']}"
    os.makedirs(scope, mode=0o700, exist_ok=True)
    digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipt = {"phase": "running", "token": request["token"], "generation": request["generation"], "digest": digest}
    with open(f"{scope}/current.json", "w", encoding="utf-8") as handle:
        json.dump(receipt, handle)
    os.makedirs("/run/praho", mode=0o700, exist_ok=True)
    lane = os.open(f"/run/praho/chain-{identity['domain_id']}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    argv = ["/usr/bin/perl", script, str(lane), *(["restore"] if mode == "restore" else [])]
    result = subprocess.run(  # noqa: S603 -- Fixed interpreter and helper inside a disposable lab node.
        argv, input=json.dumps(payload), text=True, capture_output=True, pass_fds=(lane,), check=False
    )
    print(json.dumps({"rc": result.returncode, "stdout": result.stdout, "stderr": result.stderr}))


if __name__ == "__main__":
    main()
