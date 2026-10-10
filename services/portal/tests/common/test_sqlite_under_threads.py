"""The portal's SQLite stores stay exact when a threaded worker writes them from several threads (ADR-0056).

One process, eight threads, the same file-backed SQLite database the deployed portal uses: merged
session saves, counter increments and a contended claim, all at once. Every write must land, the
counter must equal the number of increments, exactly one thread may own the claim, and no thread may
see a database error such as "database is locked".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from django.test import SimpleTestCase

PORTAL_ROOT = Path(__file__).resolve().parents[2]
THREADS = 8
STEPS = 25

HARNESS = textwrap.dedent(
    f"""
    import json, threading
    import django
    django.setup()
    from django.core.management import call_command
    from apps.common import counters
    from apps.common.session_store import SessionStore

    call_command("migrate", "sessions", verbosity=0)
    call_command("migrate", "common", verbosity=0)
    seed = SessionStore()
    seed["user_id"] = 7
    seed.save()
    key = seed.session_key
    errors, owners = [], []
    lock = threading.Lock()
    start = threading.Barrier({THREADS})

    def worker(thread):
        start.wait()
        for step in range({STEPS}):
            try:
                store = SessionStore(session_key=key)
                store[f"t{{thread}}_{{step}}"] = step
                store.save()
                counters.increment("threads:hits", 600)
                if counters.claim("threads:claim", 600, f"{{thread}}-{{step}}"):
                    with lock:
                        owners.append(f"{{thread}}-{{step}}")
            except Exception as error:  # every failure is reported, none is retried
                with lock:
                    errors.append(repr(error))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range({THREADS})]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stored = SessionStore(session_key=key)
    written = sum(1 for name in stored.keys() if name.startswith("t"))
    print(json.dumps({{"written": written, "hits": counters.peek("threads:hits"), "owners": len(owners), "errors": errors}}))
    """
)


class SQLiteUnderThreadsTests(SimpleTestCase):
    def test_sessions_counters_and_claims_stay_exact_across_threads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "DJANGO_SETTINGS_MODULE": "config.settings.dev",
                "SESSION_DB_PATH": str(Path(directory) / "portal.sqlite3"),
                "PYTHONPATH": "",
            }
            completed = subprocess.run(  # noqa: S603 -- fixed interpreter and a test-owned script
                [sys.executable, "-c", HARNESS],
                cwd=PORTAL_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(result, {"written": THREADS * STEPS, "hits": THREADS * STEPS, "owners": 1, "errors": []})
