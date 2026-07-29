"""Domain.name is stored lowercase, structurally (#442).

DNS names are case-insensitive, but ``Domain.name`` is a plain CharField with
``unique=True`` — so ``Example.RO`` and ``example.ro`` are two distinct rows to the
database, and any exact-match lookup for one silently misses the other.

That is the failure mode #430 was about, reached from the data side: the renew-item
link in ``create_domain_order_item`` looks up ``name=domain_name.lower()``, so a stored
mixed-case row never links, the item is created unlinked, and the renewal is skipped
with no error.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.models import TLD, Domain, Registrar, TLDRegistrarAssignment
from apps.orders.models import Order


class DomainNameCanonicalizationTests(TestCase):
    def setUp(self) -> None:
        self.ro = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=2300,
            renewal_price_cents=2300,
            transfer_price_cents=2300,
            min_registration_period=1,
            max_registration_period=10,
            is_active=True,
        )
        self.registrar = Registrar.objects.create(
            name="canon-registrar",
            display_name="Canon Registrar",
            website_url="https://example.test",
            status="active",
        )
        TLDRegistrarAssignment.objects.create(
            tld=self.ro,
            registrar=self.registrar,
            is_primary=True,
        )
        self.customer = Customer.objects.create(
            name="Canon Customer",
            company_name="Canon SRL",
            customer_type="company",
            primary_email="canon@example.test",
            primary_phone="+40712345678",
        )
        CustomerTaxProfile.objects.create(customer=self.customer, cui="RO12345679")
        currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-CANON-1",
            currency=currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

    def _domain(self, name: str) -> Domain:
        return Domain.objects.create(
            name=name,
            tld=self.ro,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )

    def test_mixed_case_name_is_stored_lowercase(self) -> None:
        domain = self._domain("Example.RO")

        self.assertEqual(domain.name, "example.ro")
        self.assertEqual(Domain.objects.get(pk=domain.pk).name, "example.ro")

    def test_surrounding_whitespace_is_stripped(self) -> None:
        domain = self._domain("  Spaced.RO  ")

        self.assertEqual(domain.name, "spaced.ro")

    def test_case_variants_collide_instead_of_creating_a_twin_row(self) -> None:
        """Two casings of one domain must be ONE row, not two that shadow each other."""
        self._domain("Twin.RO")

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._domain("twin.ro")

    def test_rename_to_mixed_case_is_canonicalized_too(self) -> None:
        """save() canonicalizes on every write, not just creation."""
        domain = self._domain("rename.ro")

        domain.name = "ReName.RO"
        domain.save()

        self.assertEqual(Domain.objects.get(pk=domain.pk).name, "rename.ro")

    def test_lookup_by_lowercase_finds_a_domain_created_mixed_case(self) -> None:
        """The #442 regression, at the lookup that actually breaks.

        ``create_domain_order_item`` links a renew item with
        ``Domain.objects.filter(name=domain_name.lower(), customer=...)``. Before
        canonicalization a row stored as "Renew.RO" never matched that filter, so the
        item was created unlinked and the renewal was silently skipped.

        Asserted against the filter directly rather than through
        create_domain_order_item, because the renew-linking code itself lands in #435
        (PR #435) and is not on master yet. Once that merges, the mixed-case
        regression test the review asked for can assert end-to-end.
        """
        domain = self._domain("Renew.RO")

        found = Domain.objects.filter(name="renew.ro", customer=self.customer).first()

        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found.id, domain.id)
