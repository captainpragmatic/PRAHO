"""Domain.name is stored in one structural canonical form (#442, #473).

DNS names are case-insensitive, but ``Domain.name`` is a plain CharField with
``unique=True``. ASCII input is stripped and lowercased, while internationalized
U-labels are additionally folded to their IDNA UTS-46 A-label so equivalent Unicode
and punycode spellings cannot become distinct rows or miss exact-match lookups.
"""

from __future__ import annotations

import importlib

from django.db import IntegrityError, connection, transaction
from django.db.migrations.loader import MigrationLoader
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.domain_names import canonicalize_domain_name
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

    def test_canonicalize_u_label_to_idna_a_label(self) -> None:
        self.assertEqual(canonicalize_domain_name("münchen.de"), "xn--mnchen-3ya.de")

    def test_canonicalize_invalid_unicode_falls_back_without_raising(self) -> None:
        self.assertEqual(canonicalize_domain_name("  \u0080.COM  "), "\u0080.com")

    def test_canonicalize_ascii_behavior_is_unchanged(self) -> None:
        self.assertEqual(canonicalize_domain_name("  XN--MNCHEN-3YA.DE  "), "xn--mnchen-3ya.de")
        self.assertEqual(canonicalize_domain_name("  Example.RO  "), "example.ro")

    def test_u_label_and_a_label_saves_share_one_canonical_row(self) -> None:
        cases = (
            ("münchen.de", "xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
            ("xn--zrich-kva.de", "zürich.de", "xn--zrich-kva.de"),
        )

        for first_name, second_name, canonical in cases:
            with self.subTest(first_name=first_name, second_name=second_name):
                domain = self._domain(first_name)

                self.assertEqual(domain.name, canonical)
                self.assertEqual(Domain.objects.get(name=canonical).pk, domain.pk)
                with self.assertRaises(IntegrityError), transaction.atomic():
                    self._domain(second_name)

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

    def test_queryset_update_is_canonicalized(self) -> None:
        """Bulk ORM writes bypass save() — the manager layer must canonicalize them.

        Without it, a data import doing ``Domain.objects.filter(...).update(name=...)``
        can resurrect a mixed-case row beside the canonical one, and the exact
        lowercase renew/webhook lookups miss it again — the exact bug shape this PR
        exists to make structurally impossible for every ORM writer.
        """
        domain = self._domain("bulkupd.ro")

        Domain.objects.filter(pk=domain.pk).update(name="BulkUpd.RO")

        domain.refresh_from_db()
        self.assertEqual(domain.name, "bulkupd.ro")

    def test_bulk_create_is_canonicalized(self) -> None:
        created = Domain.objects.bulk_create(
            [
                Domain(
                    name="  BulkCreate.RO ",
                    tld=self.ro,
                    registrar=self.registrar,
                    customer=self.customer,
                    status="active",
                )
            ]
        )
        stored = Domain.objects.get(pk=created[0].pk)
        self.assertEqual(stored.name, "bulkcreate.ro")

    def test_bulk_create_folds_u_label_to_idna_a_label(self) -> None:
        created = Domain.objects.bulk_create(
            [
                Domain(
                    name="bücher.ro",
                    tld=self.ro,
                    registrar=self.registrar,
                    customer=self.customer,
                    status="active",
                )
            ]
        )

        stored = Domain.objects.get(pk=created[0].pk)
        self.assertEqual(stored.name, "xn--bcher-kva.ro")

    def test_bulk_update_is_canonicalized(self) -> None:
        domain = self._domain("bulkup2.ro")
        domain.name = "BulkUp2.RO"
        # bulk_update skips save(); the manager must canonicalize the instances.
        Domain.objects.bulk_update([domain], ["name"])
        domain.refresh_from_db()
        self.assertEqual(domain.name, "bulkup2.ro")

    def test_bulk_create_accepts_a_generator(self) -> None:
        """The canonicalizing override must not exhaust an iterable before delegating.

        Django's bulk_create accepts any iterable; an override that loops over a
        generator and then hands the SAME (now spent) generator to super() silently
        creates zero rows and returns [] — data loss dressed as success.
        """
        created = Domain.objects.bulk_create(
            Domain(
                name=name,
                tld=self.ro,
                registrar=self.registrar,
                customer=self.customer,
                status="active",
            )
            for name in ["GenOne.RO", "gentwo.ro"]
        )
        self.assertEqual(len(created), 2)
        self.assertTrue(Domain.objects.filter(name="genone.ro").exists())
        self.assertTrue(Domain.objects.filter(name="gentwo.ro").exists())

    def test_save_with_empty_update_fields_stays_a_no_op(self) -> None:
        """Django documents save(update_fields=[]) as 'skip the write entirely'.

        Canonicalization must not turn that guaranteed no-op into an UPDATE by
        appending "name" to an empty list.
        """
        domain = self._domain("noopfields.ro")
        Domain._base_manager.filter(pk=domain.pk).update(name="NoopFields.RO")
        stale = Domain.objects.get(pk=domain.pk)

        stale.save(update_fields=[])  # documented no-op — nothing may be written

        self.assertEqual(Domain._base_manager.get(pk=domain.pk).name, "NoopFields.RO")

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

    def test_renew_order_item_links_despite_padded_mixed_case_input(self) -> None:
        """Input-side canonicalization: validation strips/lowers only a LOCAL copy,
        so a renew request for "  RenewWS.RO  " used to pass validation and then
        miss the stored row at the caller's ``.lower()``-only lookup — an unlinked
        item and a silently skipped renewal, from the input side this time.
        """
        domain = self._domain("renewws.ro")

        ok, item = DomainOrderService.create_domain_order_item(self.order, "  RenewWS.RO  ", "renew")

        self.assertTrue(ok, f"service refused the renew item: {item!r}")
        assert not isinstance(item, str)
        self.assertIsNotNone(item.domain)
        assert item.domain is not None
        self.assertEqual(item.domain.id, domain.id)
        self.assertEqual(item.domain_name, "renewws.ro")

    def test_save_with_update_fields_persists_canonicalized_name(self) -> None:
        """save(update_fields=[...]) must not diverge memory from database.

        If a non-canonical row exists (raw SQL / legacy) and code calls
        save(update_fields=["status"]), the override canonicalizes self.name in
        memory — but without adding "name" to update_fields the DB keeps the old
        value, and the exact-match lookups keep missing it while the in-memory
        object looks fine.
        """
        domain = self._domain("updfields.ro")
        Domain._base_manager.filter(pk=domain.pk).update(name="UpdFields.RO")
        stale = Domain.objects.get(pk=domain.pk)
        self.assertEqual(stale.name, "UpdFields.RO")  # non-canonical row, as raw SQL would leave it

        stale.auto_renew = False
        stale.save(update_fields=["auto_renew"])

        self.assertEqual(Domain._base_manager.get(pk=domain.pk).name, "updfields.ro")


class CanonicalizationMigrationTests(TestCase):
    """The canonicalization migrations must fail loudly on every collision shape
    and rewrite every legacy row covered by their respective canonical forms.

    Rows are seeded via queryset ``update()`` to bypass the current ``save()``
    canonicalization, reproducing what older writers could actually store.
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
        """Create a row whose stored name bypasses ALL canonicalization layers.

        ``_base_manager`` is the deliberate plain escape hatch: ``objects`` now
        canonicalizes ``update()`` too, so only the base manager can reproduce what a
        pre-#442 writer stored. The post-seed assertion guards these tests against
        going vacuous — if seeding ever canonicalizes, the migration tests would
        otherwise "pass" while testing nothing.
        """
        domain = Domain.objects.create(
            name=f"placeholder-{stored_name.strip().lower()}",
            tld=self.ro,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )
        Domain._base_manager.filter(pk=domain.pk).update(name=stored_name)
        domain.refresh_from_db()
        assert domain.name == stored_name, f"legacy seeding was canonicalized: {domain.name!r}"
        return domain

    def _run_migration(self) -> None:
        """Invoke the migration function against the HISTORICAL model state.

        The real executor hands RunPython a historical apps registry whose Domain has
        NO custom save() — running these tests with the live registry would let live-
        model canonicalization mask a migration that forgot to rewrite the rows.
        """
        module = importlib.import_module("apps.domains.migrations.0006_canonicalize_domain_name")
        loader = MigrationLoader(connection)
        state = loader.project_state(("domains", "0005_tld_tld_min_registration_period_lte_max"))
        module.canonicalize_names(state.apps, None)

    def _run_idn_migration(self) -> None:
        module = importlib.import_module("apps.domains.migrations.0007_canonicalize_idn_domain_names")
        loader = MigrationLoader(connection)
        state = loader.project_state(("domains", "0006_canonicalize_domain_name"))
        module.canonicalize_names(state.apps, None)

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

    def test_idn_row_is_canonicalized_to_a_label(self) -> None:
        row = self._legacy_domain("MÜNCHEN.RO")

        self._run_idn_migration()

        row.refresh_from_db()
        self.assertEqual(row.name, "xn--mnchen-3ya.ro")

    def test_existing_a_label_twin_fails_before_rewriting_u_label(self) -> None:
        a_label = self._legacy_domain("xn--mnchen-3ya.ro")
        u_label = Domain.objects.create(
            name="idn-collision-placeholder.ro",
            tld=self.ro,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
        )
        Domain._base_manager.filter(pk=u_label.pk).update(name="münchen.ro")
        u_label.refresh_from_db()
        self.assertEqual(u_label.name, "münchen.ro")

        with self.assertRaisesMessage(RuntimeError, "xn--mnchen-3ya.ro"):
            self._run_idn_migration()

        a_label.refresh_from_db()
        u_label.refresh_from_db()
        self.assertEqual(a_label.name, "xn--mnchen-3ya.ro")
        self.assertEqual(u_label.name, "münchen.ro")
