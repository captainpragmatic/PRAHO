"""The schema comparator writes its connection string into every dump it produces.

Those dumps are kept as evidence and may be shared, so the password must be gone from them in
every libpq form: URL, unquoted keyword, and quoted keyword containing spaces or escaped quotes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("compare_db_schema_under_test", ROOT / "scripts/compare_db_schema.py")
assert spec is not None and spec.loader is not None
compare_db_schema = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare_db_schema)


class DsnRedactionTests(SimpleTestCase):
    def test_no_form_of_the_password_survives(self) -> None:
        cases = {
            "url": "postgresql://test:hunter2@127.0.0.1:5432/praho",
            "keyword": "host=127.0.0.1 user=test password=hunter2 dbname=praho",
            "quoted with a space": "host=127.0.0.1 user=test password='hunter2 tail' dbname=praho",
            "quoted with an escaped quote": r"host=127.0.0.1 user=test password='hun\'ter2 tail' dbname=praho",
        }
        for label, dsn in cases.items():
            with self.subTest(label):
                redacted = compare_db_schema._redact_dsn(dsn)
                self.assertNotIn("hunter2", redacted.replace("hun\\'ter2", "hunter2"))
                self.assertNotIn("hun'ter2", redacted)
                self.assertNotIn("tail", redacted)
                self.assertIn("praho", redacted)

    def test_an_unparseable_dsn_is_withheld_entirely(self) -> None:
        self.assertNotIn("hunter2", compare_db_schema._redact_dsn("password='hunter2 unterminated"))
