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

import importlib

from django.apps import apps as django_apps
from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.models import TLD, Domain, Registrar, TLDRegistrarAssignment
from apps.domains.services import DomainOrderService
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
        """The #442 regression, at the exact lookup shape that breaks.

        ``create_domain_order_item`` links a renew item with
        ``Domain.objects.filter(name=domain_name.lower(), customer=...)``. Before
        canonicalization a row stored as "Renew.RO" never matched that filter, so the
        item was created unlinked and the renewal was silently skipped.
        """
        domain = self._domain("Renew.RO")

        found = Domain.objects.filter(name="renew.ro", customer=self.customer).first()

        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found.id, domain.id)

    def test_renew_order_item_links_mixed_case_created_domain_end_to_end(self) -> None:
        """The full #442 → #435 chain: a mixed-case-created domain still gets its
        renew order item LINKED (not silently unlinked) through the real service.

        This is the end-to-end assertion the original review deferred while the
        renew-linking code (#435) was not yet on master. It is red without
        canonicalization: the stored "RenewE2E.RO" never matches the service's
        ``filter(name=domain_name.lower())`` and the item is created with
        ``domain=None`` — the silent-skip failure this PR exists to prevent.
        """
        domain = self._domain("RenewE2E.RO")

        ok, item = DomainOrderService.create_domain_order_item(self.order, "renewe2e.ro", "renew")

        self.assertTrue(ok, f"service refused the renew item: {item!r}")
        assert not isinstance(item, str)
        self.assertIsNotNone(item.domain)
        assert item.domain is not None
        self.assertEqual(item.domain.id, domain.id)


class CanonicalizationMigrationTests(TestCase):
    """The 0006 data migration must fail LOUDLY on every collision shape and must
    canonicalize every non-canonical row — including whitespace-only variants.

    Rows are seeded via queryset ``update()`` to bypass the new ``save()``
    canonicalization, reproducing what pre-#442 writers could actually store.
    """

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
            name="mig-registrar",
            display_name="Mig Registrar",
            website_url="https://example.test",
            status="active",
        )
        self.customer = Customer.objects.create(
            name="Mig Customer",
            company_name="Mig SRL",
            customer_type="company",
            primary_email="mig@example.test",
            primary_phone="+40712345670",
        )

    def _legacy_domain(self, stored_name: str) -> Domain:
        """Create a row whose stored name bypasses save()-canonicalization."""
        domain = Domain.objects.create(
            name=f"placeholder-{stored_name.strip().lower()}",
            tld=self.ro,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )
        Domain.objects.filter(pk=domain.pk).update(name=stored_name)
        domain.refresh_from_db()
        return domain

    def _run_migration(self) -> None:
        module = importlib.import_module("apps.domains.migrations.0006_canonicalize_domain_name")
        module.canonicalize_names(django_apps, None)

    def test_mixed_case_row_is_canonicalized(self) -> None:
        row = self._legacy_domain("Example.RO")
        self._run_migration()
        row.refresh_from_db()
        self.assertEqual(row.name, "example.ro")

    def test_whitespace_only_variant_is_canonicalized(self) -> None:
        """A row that is lowercase but padded ("  spaced.ro  ") is just as
        non-canonical as a mixed-case one — the exact-match lookups miss it the
        same way — and must not be skipped by a case-only queryset.
        """
        row = self._legacy_domain("  spaced.ro  ")
        self._run_migration()
        row.refresh_from_db()
        self.assertEqual(row.name, "spaced.ro")

    def test_existing_lowercase_twin_fails_loudly(self) -> None:
        self._legacy_domain("twin.ro")  # canonical occupant
        self._legacy_domain("Twin.RO")  # would collide on lowering
        with self.assertRaisesMessage(RuntimeError, "Twin.RO"):
            self._run_migration()

    def test_pairwise_mixed_case_twins_fail_loudly_not_with_integrity_error(self) -> None:
        """Two MIXED-case rows lowering to the same target ("Pair.RO" + "PAIR.ro")
        have no existing-lowercase occupant, so an existing-row check alone misses
        them and the loop dies midway on a raw IntegrityError — after already
        rewriting some rows. The migration must detect duplicate TARGETS among the
        rows it is about to rewrite and refuse up front, with the offending names.
        """
        self._legacy_domain("Pair.RO")
        self._legacy_domain("PAIR.ro")
        with self.assertRaisesMessage(RuntimeError, "pair.ro"):
            self._run_migration()
