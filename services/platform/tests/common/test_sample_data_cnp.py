"""Sample individuals have valid CNPs on both database backends.

The random sample customers used `index % 10` as the check digit and county codes up to 52, so
most of their CNPs failed validation.
"""

from __future__ import annotations

from datetime import date

from django.test import TestCase
from faker import Faker

from apps.common.cnp_validator import CNPValidator
from apps.common.management.commands.generate_sample_data import Command, _random_cnp
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


class RandomCNPTests(TestCase):
    def test_random_individuals_have_valid_cnps(self) -> None:
        fake = Faker("ro_RO")
        fake.seed_instance(4)
        for index in range(60):
            with self.subTest(index=index):
                cnp = _random_cnp(fake, index)
                result = CNPValidator.validate(cnp)
                self.assertTrue(result.is_valid, f"{cnp}: {result.error_message}")
