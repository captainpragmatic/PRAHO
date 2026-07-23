# ===============================================================================
# BILLING SEQUENCES TESTS (Django TestCase Format)
# ===============================================================================

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.billing.models import InvoiceSequence, ProformaSequence
from apps.billing.services import InvoiceNumberingService

User = get_user_model()


class InvoiceSequenceTestCase(TestCase):
    """Test InvoiceSequence model functionality"""

    def test_create_invoice_sequence(self):
        """Test basic invoice sequence creation"""
        sequence = InvoiceSequence.objects.create(
            scope='default',
            last_value=0
        )

        self.assertEqual(sequence.scope, 'default')
        self.assertEqual(sequence.last_value, 0)

    def test_invoice_sequence_str_representation(self):
        """Test string representation"""
        sequence = InvoiceSequence.objects.create(
            scope='romania',
            last_value=100
        )

        str_repr = str(sequence)
        # Just verify it doesn't crash
        self.assertIsInstance(str_repr, str)

    def test_invoice_sequence_unique_constraint(self):
        """Test unique constraint on scope"""
        InvoiceSequence.objects.create(
            scope='default',
            last_value=1
        )

        # Should not be able to create another sequence with same scope
        with transaction.atomic(), self.assertRaises(IntegrityError):
            InvoiceSequence.objects.create(
                scope='default',
                last_value=1
            )

    def test_invoice_sequence_different_scopes_allowed(self):
        """Test that different scopes are allowed"""
        seq_default = InvoiceSequence.objects.create(
            scope='default',
            last_value=1
        )

        seq_ro = InvoiceSequence.objects.create(
            scope='romania',
            last_value=1
        )

        self.assertEqual(seq_default.scope, 'default')
        self.assertEqual(seq_ro.scope, 'romania')

    def test_invoice_sequence_get_next_number_default(self):
        """Test getting next invoice number with default prefix"""
        sequence = InvoiceSequence.objects.create(
            scope='default',
            last_value=0
        )

        # Get first number
        number1 = sequence.get_next_number()
        self.assertEqual(number1, 'INV-000001')
        self.assertEqual(sequence.last_value, 1)

        # Get second number
        number2 = sequence.get_next_number()
        self.assertEqual(number2, 'INV-000002')
        self.assertEqual(sequence.last_value, 2)

    def test_invoice_sequence_uses_its_persisted_series_prefix(self) -> None:
        """The active legal series owns its prefix; callers must not hardcode it."""
        sequence = InvoiceSequence.objects.create(
            scope="default",
            prefix="INV-2027",
            last_value=0,
        )

        number = sequence.get_next_number()

        self.assertEqual(number, "INV-2027-000001")

    def test_next_number_preview_does_not_consume_the_sequence(self) -> None:
        sequence = InvoiceSequence.objects.create(
            scope="default",
            prefix="INV-2027",
            last_value=42,
        )

        self.assertEqual(sequence.next_number_preview, "INV-2027-000043")
        sequence.refresh_from_db()
        self.assertEqual(sequence.last_value, 42)

    def test_invoice_sequence_rejects_per_call_prefix_override(self) -> None:
        """A caller cannot silently change the legal prefix for one invoice."""
        sequence = InvoiceSequence.objects.create(
            scope='romania',
            last_value=0
        )

        with self.assertRaises(TypeError):
            sequence.get_next_number(prefix='INVOICE')
        with self.assertRaises(TypeError):
            sequence.get_next_number('INVOICE')

        sequence.refresh_from_db()
        self.assertEqual(sequence.last_value, 0)

    def test_invoice_sequence_increment_behavior(self):
        """Test sequence increment behavior"""
        sequence = InvoiceSequence.objects.create(
            scope='test',
            last_value=99
        )

        # Should increment from 99 to 100
        number = sequence.get_next_number()
        self.assertEqual(number, 'INV-000100')
        self.assertEqual(sequence.last_value, 100)

    def test_invoice_sequence_high_numbers(self):
        """Test sequence with high numbers"""
        sequence = InvoiceSequence.objects.create(
            scope='high',
            last_value=999999
        )

        number = sequence.get_next_number()
        self.assertEqual(number, 'INV-1000000')  # Should be 7 digits for million
        self.assertEqual(sequence.last_value, 1000000)


class ProformaSequenceTestCase(TestCase):
    """Test ProformaSequence model functionality"""

    def test_create_proforma_sequence(self):
        """Test basic proforma sequence creation"""
        sequence = ProformaSequence.objects.create(
            scope='default',
            last_value=0
        )

        self.assertEqual(sequence.scope, 'default')
        self.assertEqual(sequence.last_value, 0)

    def test_proforma_sequence_unique_constraint(self):
        """Test unique constraint on scope"""
        ProformaSequence.objects.create(
            scope='default',
            last_value=1
        )

        # Should not be able to create another sequence with same scope
        with transaction.atomic(), self.assertRaises(IntegrityError):
            ProformaSequence.objects.create(
                scope='default',
                last_value=1
            )

    def test_proforma_sequence_get_next_number_default(self):
        """Test getting next proforma number with default prefix"""
        sequence = ProformaSequence.objects.create(
            scope='default',
            last_value=0
        )

        # Get first number
        number1 = sequence.get_next_number()
        self.assertEqual(number1, 'PRO-000001')
        self.assertEqual(sequence.last_value, 1)

        # Get second number
        number2 = sequence.get_next_number()
        self.assertEqual(number2, 'PRO-000002')
        self.assertEqual(sequence.last_value, 2)

    def test_proforma_sequence_get_next_number_custom_prefix(self):
        """Test getting next proforma number with custom prefix"""
        sequence = ProformaSequence.objects.create(
            scope='romania',
            last_value=0
        )

        # Get number with custom prefix
        number = sequence.get_next_number('PROFORMA')
        self.assertEqual(number, 'PROFORMA-000001')
        self.assertEqual(sequence.last_value, 1)

    def test_proforma_sequence_increment_behavior(self):
        """Test sequence increment behavior"""
        sequence = ProformaSequence.objects.create(
            scope='test',
            last_value=50
        )

        # Should increment from 50 to 51
        number = sequence.get_next_number()
        self.assertEqual(number, 'PRO-000051')
        self.assertEqual(sequence.last_value, 51)


class SequenceIntegrationTestCase(TestCase):
    """Test sequence integration scenarios"""

    def test_multiple_sequence_types(self):
        """Test creating both invoice and proforma sequences"""
        invoice_seq = InvoiceSequence.objects.create(
            scope='main',
            last_value=0
        )

        proforma_seq = ProformaSequence.objects.create(
            scope='main',
            last_value=0
        )

        # They can have same scope since they're different models
        self.assertEqual(invoice_seq.scope, 'main')
        self.assertEqual(proforma_seq.scope, 'main')

    def test_sequence_multiple_scopes(self):
        """Test multiple scopes for different business needs"""
        # Default scope
        default_inv = InvoiceSequence.objects.create(
            scope='default',
            last_value=0
        )

        # Romania specific scope
        romania_inv = InvoiceSequence.objects.create(
            scope='romania',
            prefix='RO-INV',
            last_value=0
        )

        # Test scope
        test_inv = InvoiceSequence.objects.create(
            scope='test',
            prefix='TEST',
            last_value=1000
        )

        # Each should operate independently
        default_num = default_inv.get_next_number()
        romania_num = romania_inv.get_next_number()
        test_num = test_inv.get_next_number()

        self.assertEqual(default_num, 'INV-000001')
        self.assertEqual(romania_num, 'RO-INV-000001')
        self.assertEqual(test_num, 'TEST-001001')  # Starts from 1001

    def test_sequence_concurrent_usage_simulation(self):
        """Test sequence behavior under simulated concurrent usage"""
        sequence = InvoiceSequence.objects.create(
            scope='concurrent',
            prefix='CONC',
            last_value=0
        )

        # Simulate multiple requests getting numbers
        numbers = []
        for _i in range(5):
            number = sequence.get_next_number()
            numbers.append(number)

        # All numbers should be sequential and unique
        expected_numbers = [
            'CONC-000001',
            'CONC-000002',
            'CONC-000003',
            'CONC-000004',
            'CONC-000005'
        ]

        self.assertEqual(numbers, expected_numbers)
        self.assertEqual(sequence.last_value, 5)

    def test_sequence_format_consistency(self):
        """Test that sequence number format is consistent"""
        sequence = InvoiceSequence.objects.create(
            scope='format',
            prefix='TEST',
            last_value=0
        )

        # Test various numbers to ensure 6-digit padding
        test_cases = [
            (1, 'TEST-000001'),
            (10, 'TEST-000010'),
            (100, 'TEST-000100'),
            (1000, 'TEST-001000'),
            (10000, 'TEST-010000'),
            (100000, 'TEST-100000'),
        ]

        for expected_value, expected_format in test_cases:
            # Set the sequence to the value - 1 so get_next_number returns the expected value
            sequence.last_value = expected_value - 1
            sequence.save()

            number = sequence.get_next_number()
            self.assertEqual(number, expected_format)

    def test_sequence_prefix_variations(self):
        """Test various prefix formats"""
        prefixes = ['INV', 'INVOICE', 'F-2024', 'REC', '001-BILL']

        for index, prefix in enumerate(prefixes):
            sequence = InvoiceSequence.objects.create(scope=f'prefix_{index}', prefix=prefix, last_value=0)
            number = sequence.get_next_number()
            self.assertEqual(number, f'{prefix}-000001')

    def test_sequence_reset_simulation(self):
        """Test sequence reset scenario (for new year, etc.)"""
        sequence = InvoiceSequence.objects.create(scope='yearly-2024', prefix='2024', last_value=999)

        # Generate a number at end of year
        end_year_number = sequence.get_next_number()
        self.assertEqual(end_year_number, '2024-001000')

        # A new year is a new immutable series, not a counter edit.
        next_year = InvoiceSequence.objects.create(scope='yearly-2025', prefix='2025', last_value=0)
        new_year_number = next_year.get_next_number()
        self.assertEqual(new_year_number, '2025-000001')

    def test_sequence_persistence(self):
        """Test that sequence persists across object reloads"""
        sequence = InvoiceSequence.objects.create(
            scope='persist',
            last_value=0
        )

        # Get a number
        number1 = sequence.get_next_number()

        # Reload from database
        sequence.refresh_from_db()

        # Should continue from where it left off
        number2 = sequence.get_next_number()

        self.assertEqual(number1, 'INV-000001')
        self.assertEqual(number2, 'INV-000002')

    def test_sequence_edge_cases(self):
        """Test sequence edge cases"""
        sequence = InvoiceSequence.objects.create(scope='edge', prefix='I', last_value=0)

        number = sequence.get_next_number()
        self.assertEqual(number, 'I-000001')


# ===============================================================================
# MIGRATED FROM test_sequences_concurrency.py
# ===============================================================================


class InvoiceSequenceConcurrencyMigratedTests(TestCase):
    """Tests migrated from test_sequences_concurrency.py"""

    def test_sequential_numbers_unique_and_incrementing(self) -> None:
        seq = InvoiceSequence.objects.create(scope='test_conc', prefix='TST', last_value=0)

        numbers: list[str] = [seq.get_next_number() for _ in range(10)]

        # Ensure uniqueness and ascending sequence
        self.assertEqual(len(numbers), len(set(numbers)))
        expected_last = 10
        self.assertEqual(seq.last_value, expected_last)

    def test_prefix_and_padding(self) -> None:
        seq = InvoiceSequence.objects.create(scope='pad_test', prefix='PAD', last_value=999)
        number = seq.get_next_number()
        # Should increment to 1000 and padded accordingly
        self.assertTrue(number.startswith('PAD-'))
        self.assertTrue(number.endswith('001000'))

    def test_numbering_service_recovers_when_another_worker_creates_the_scope(self) -> None:
        sequence = InvoiceSequence.objects.create(scope="default", prefix="INV", last_value=0)
        locked_queryset = MagicMock()
        locked_queryset.get.side_effect = [InvoiceSequence.DoesNotExist, sequence]

        with patch.object(InvoiceSequence.objects, "select_for_update", return_value=locked_queryset):
            number = InvoiceNumberingService.get_next_number()

        self.assertEqual(number, "INV-000001")
