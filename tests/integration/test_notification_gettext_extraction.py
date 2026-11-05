"""The notification fallback must be extractable by the real CI gettext tool."""

import ast
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ("notifications/models.py", "Marketing opt-out", 1),
    ("orders/services.py", "This domain is on the order twice.", 1),
    ("promotions/admin.py", "Unresolved currency", 1),
    ("promotions/money_history.py", "Unresolved currency", 1),
    ("promotions/gift_delivery.py", "Funding receipt", 2),
)


class NotificationGettextExtractionTests(unittest.TestCase):
    def test_notification_and_money_labels_retain_every_real_gettext_occurrence(self) -> None:
        executable = shutil.which("xgettext")
        if executable is None:
            self.fail("Install GNU gettext before running the extraction regression")
        self.assertEqual(
            sum(count for _path, _message, count in CASES), 6, "Keep the final affected site in the census"
        )
        for relative, message, count in CASES:
            with self.subTest(source=relative, message=message), tempfile.TemporaryDirectory() as directory:
                source = ROOT / "services/platform/apps" / relative
                calls = {
                    node.args[0].lineno
                    for node in ast.walk(ast.parse(source.read_text()))
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == message
                }
                self.assertEqual(len(calls), count, "The extraction check must exercise every affected call")
                output = Path(directory) / "extracted.po"
                result = subprocess.run(  # noqa: S603 -- Real extractor, actual source and owned output; no shell.
                    [
                        executable,
                        "--language=Python",
                        "--keyword=_",
                        "--from-code=UTF-8",
                        f"--output={output}",
                        str(source),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                entry = next(
                    (entry for entry in output.read_text().split("\n\n") if f'msgid "{message}"' in entry.splitlines()),
                    None,
                )
                self.assertIsNotNone(entry, f"The real extractor lost {message!r} from {relative}")
                if entry is not None:
                    occurrences = {
                        int(reference.rsplit(":", 1)[1])
                        for line in entry.splitlines()
                        if line.startswith("#:")
                        for reference in line[2:].split()
                    }
                    self.assertEqual(occurrences, calls)
