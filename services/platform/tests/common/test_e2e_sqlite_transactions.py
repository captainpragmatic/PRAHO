"""The threaded browser server reserves SQLite writes before transactional reads."""

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase


class E2ESQLiteTransactionTests(SimpleTestCase):
    def test_atomic_read_reserves_the_writer_before_a_competing_request(self) -> None:
        env = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}}
        env.update(DJANGO_SETTINGS_MODULE="config.settings.e2e", PRAHO_SKIP_DOTENV="1")
        result = subprocess.run(  # noqa: S603 -- fixed local interpreter/source, isolated temporary database
            [
                sys.executable,
                "-c",
                """
import sqlite3
import tempfile
from pathlib import Path
import django
from django.conf import settings

with tempfile.TemporaryDirectory(prefix='praho-e2e-transaction-') as directory:
    settings.DATABASES['default']['NAME'] = str(Path(directory) / 'canary.sqlite3')
    django.setup()
    from django.db import connection, transaction
    with connection.cursor() as cursor:
        cursor.execute('CREATE TABLE canary (value INTEGER NOT NULL)')
        cursor.execute('INSERT INTO canary VALUES (1)')
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute('SELECT value FROM canary')
            assert cursor.fetchone() == (1,)
            competitor = sqlite3.connect(settings.DATABASES['default']['NAME'], timeout=0)
            try:
                try:
                    competitor.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError as error:
                    assert str(error) == 'database is locked', str(error)
                else:
                    competitor.rollback()
                    raise AssertionError('Transactional read did not reserve the SQLite writer')
            finally:
                competitor.close()
            cursor.execute('UPDATE canary SET value = value + 1')
    with connection.cursor() as cursor:
        cursor.execute('SELECT value FROM canary')
        assert cursor.fetchone() == (2,)
    connection.close()
print('Read and write committed once with the competing writer excluded')
""",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Read and write committed once", result.stdout)
