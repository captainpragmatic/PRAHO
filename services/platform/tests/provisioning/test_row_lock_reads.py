"""Provisioning locks rows with FOR UPDATE OF self join-free and reads related rows after the lock.

PostgreSQL docs, "Transaction Isolation" (Read Committed): a SELECT ... FOR UPDATE that waits for a
concurrent update re-checks only the newest version of the row it locks; rows joined in the same
statement keep the values of the statement's starting snapshot.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

from apps.common.row_lock_scanner import lock_join_lines

PROVISIONING = Path(__file__).resolve().parents[2] / "apps" / "provisioning"


class LockJoinDetectionTests(SimpleTestCase):
    def test_catches_either_order_and_calls_in_between(self) -> None:
        cases = {
            'M.objects.select_for_update().select_related("service").get(pk=1)': [1],
            'M.objects.select_for_update(of=("self",)).select_related("service").get(pk=1)': [1],
            'M.objects.select_related("service").select_for_update(of=("self",)).get(pk=1)': [1],
            'M.objects.select_for_update(of=("self",)).filter(pk=1).select_related("a__b").first()': [1],
            'M.objects.select_related("s").filter(pk=1).select_for_update(no_key=True, of=("self",))': [1],
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), expected)

    def test_ignores_separate_statements_and_cleared_joins(self) -> None:
        cases = (
            'M.objects.select_for_update().select_related("service").select_related(None).get(pk=1)',
            'a = M.objects.select_for_update(of=("self",)).get(pk=1)\nb = M.objects.select_related("s").get(pk=1)',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), [])


class RowLockReadsTests(SimpleTestCase):
    def test_no_row_lock_joins_rows_it_does_not_lock(self) -> None:
        offenders = [
            f"{path.relative_to(PROVISIONING)}:{line}"
            for path in sorted(PROVISIONING.rglob("*.py"))
            if "migrations" not in path.parts
            for line in lock_join_lines(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])
