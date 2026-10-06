"""Permutation individuals have valid CNPs on both database backends."""

from __future__ import annotations

from datetime import date

from django.test import TestCase

from apps.common.cnp_validator import CNPValidator
from apps.common.management.commands.generate_sample_data import Command
from apps.customers.models import Customer, CustomerTaxProfile


class PermutationCNPTests(TestCase):
    def test_individual_permutations_have_valid_cnp_and_correct_century(self) -> None:
        command = Command()
        for index in (1, 3, 6):
            with self.subTest(index=index):
                customer = Customer.objects.create(
                    name=f"Individual {index}",
                    customer_type="individual",
                    primary_email=f"individual-{index}@example.test",
                )
                command._perm_tax_profile(customer, index)
                profile = CustomerTaxProfile.objects.get(customer=customer)
                self.assertEqual(len(profile.cnp), 13)
                result = CNPValidator.validate(profile.cnp)
                self.assertTrue(result.is_valid, result.error_message)
                self.assertEqual(result.birth_date, date(1985 + index * 3, 1, 1))
