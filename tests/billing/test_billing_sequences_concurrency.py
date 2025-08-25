# ===============================================================================
# BILLING SEQUENCE CONCURRENCY TESTS
# ===============================================================================
from typing import List

from django.test import TestCase

from apps.billing.models import InvoiceSequence


class InvoiceSequenceConcurrencyTests(TestCase):
    """Simple tests to ensure InvoiceSequence.get_next_number increments atomically."""

    def test_sequential_numbers_unique_and_incrementing(self) -> None:
        seq = InvoiceSequence.objects.create(scope='test_conc', last_value=0)

        numbers: List[str] = []
        for _ in range(10):
            numbers.append(seq.get_next_number('TST'))

        # Ensure uniqueness and ascending sequence
        self.assertEqual(len(numbers), len(set(numbers)))
        expected_last = 10
        self.assertEqual(seq.last_value, expected_last)

    def test_prefix_and_padding(self) -> None:
        seq = InvoiceSequence.objects.create(scope='pad_test', last_value=999)
        number = seq.get_next_number('PAD')
        # Should increment to 1000 and padded accordingly
        self.assertTrue(number.startswith('PAD-'))
        self.assertTrue(number.endswith('001000'))
