"""Disjoint catalog edits cannot jointly create a directed cycle."""

from threading import Event
from unittest import skipUnless

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase

from apps.products.models import Product, ProductRelationship
from apps.products.upgrade_paths import save_upgrade_path
from apps.users.models import User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and independent connections")
class UpgradePathGraphConcurrencyTests(TransactionTestCase):
    def test_new_product_and_ordinary_fk_reference_commit_while_graph_edit_is_held(self) -> None:
        actor = User.objects.create_user(email="graph-references@example.com", staff_role="admin")
        first = Product.objects.create(slug="reference-small", name="Reference small", product_type="shared_hosting")
        second = Product.objects.create(slug="reference-large", name="Reference large", product_type="shared_hosting")

        def add_unrelated_reference():
            new_product = Product.objects.create(
                slug="new-reference", name="New reference", product_type="shared_hosting"
            )
            reference = ProductRelationship.objects.create(
                source_product_id=first.pk, target_product_id=new_product.pk, relationship_type="cross_sell"
            )
            return reference.pk

        with transaction.atomic():
            save_upgrade_path(actor=actor, source_product_id=first.pk, target_product_id=second.pk)
            with database_worker(add_unrelated_reference) as (_pid, pending):
                reference_id = pending.result(timeout=10)
        self.assertTrue(ProductRelationship.objects.filter(pk=reference_id, relationship_type="cross_sell").exists())

    def test_disjoint_mutations_wait_and_recheck_the_entire_committed_graph(self) -> None:
        actor = User.objects.create_user(email="graph-concurrency@example.com", staff_role="admin")
        products = [
            Product.objects.create(slug=f"graph-{index}", name=f"Graph {index}", product_type="shared_hosting")
            for index in range(4)
        ]
        first, second, third, fourth = products
        for source, target in ((first, second), (third, fourth)):
            save_upgrade_path(actor=actor, source_product_id=source.pk, target_product_id=target.pk)
        start = Event()

        def close_cycle():
            if not start.wait(10):
                raise AssertionError("The first graph edit never acquired its locks")
            return save_upgrade_path(actor=actor, source_product_id=fourth.pk, target_product_id=first.pk)

        with database_worker(close_cycle) as (pid, pending):
            try:
                with transaction.atomic():
                    blocker = backend_pid()
                    save_upgrade_path(actor=actor, source_product_id=second.pk, target_product_id=third.pk)
                    start.set()
                    sql = wait_for_blocker(pid, blocker, pending, table="products")
                    self.assertIn("FOR NO KEY UPDATE", sql)
                    self.assertNotIn("JOIN", sql)
            finally:
                start.set()
            with self.assertRaisesMessage(ValidationError, "cycle"):
                pending.result(timeout=20)
        self.assertEqual(ProductRelationship.objects.filter(relationship_type="upgrades_to").count(), 3)
