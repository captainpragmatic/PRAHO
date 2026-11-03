"""Catalog administrators configure a directed upgrade graph through real staff views."""

from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.products.models import Product, ProductRelationship
from apps.users.models import User
from tests.helpers.csrf import body_csrf_token
from tests.ui.node_harness import Markup


class UpgradePathEditorTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(email="upgrade-catalog-admin@example.com", staff_role="admin")
        self.support = User.objects.create_user(email="upgrade-catalog-support@example.com", staff_role="support")
        self.products = [
            Product.objects.create(slug=name, name=name.title(), product_type="shared_hosting")
            for name in ("small", "medium", "large", "other")
        ]
        self.small, self.medium, self.large, self.other = self.products
        self.client.force_login(self.admin)

    def page(self, product=None):
        return f"/products/{(product or self.small).slug}/upgrade-paths/"

    def create(self, target=None, *, active=True, order=0, source=None):
        return self.client.post(
            self.page(source) + "create/",
            {"target_product": (target or self.medium).pk, "is_active": "on" if active else "", "sort_order": order},
        )

    def edge(self, source=None, target=None, **extra):
        return ProductRelationship.objects.create(
            source_product=source or self.small,
            target_product=target or self.medium,
            relationship_type="upgrades_to",
            **extra,
        )

    def test_admin_can_create_edit_deactivate_and_remove_without_touching_other_types(self) -> None:
        unrelated = ProductRelationship.objects.create(
            source_product=self.small, target_product=self.medium, relationship_type="includes", config={"seats": 3}
        )
        response = self.create(order=3)
        self.assertEqual(response.status_code, 302)
        edge = ProductRelationship.objects.get(relationship_type="upgrades_to")
        self.assertEqual(
            (edge.source_product_id, edge.target_product_id, edge.sort_order), (self.small.pk, self.medium.pk, 3)
        )
        edge.config = {"operator_note": "Preserve existing metadata"}
        edge.save(update_fields=["config"])
        edit = self.page() + f"{edge.pk}/edit/"
        self.assertContains(self.client.get(edit), "Edit upgrade path")
        response = self.client.post(edit, {"target_product": self.large.pk, "sort_order": 7})
        self.assertEqual(response.status_code, 302)
        edge.refresh_from_db()
        self.assertEqual(edge.target_product_id, self.large.pk)
        self.assertFalse(edge.is_active)
        self.assertEqual(edge.config, {"operator_note": "Preserve existing metadata"})
        response = self.client.post(self.page() + f"{edge.pk}/remove/")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ProductRelationship.objects.filter(pk=edge.pk).exists())
        unrelated.refresh_from_db()
        self.assertEqual(unrelated.config, {"seats": 3})
        events = AuditEvent.objects.filter(
            user=self.admin, object_id=str(edge.pk), content_type__model="productrelationship"
        )
        self.assertEqual(set(events.values_list("action", flat=True)), {"create", "update", "delete"})
        self.assertTrue(all(event.metadata["relationship_type"] == "upgrades_to" for event in events))

    def test_readable_forward_reverse_and_inactive_links_have_working_admin_navigation(self) -> None:
        self.edge()
        self.edge(target=self.large, is_active=False)
        page = self.client.get(self.page())
        self.assertContains(page, "Medium")
        self.assertContains(page, "Large")
        self.assertContains(page, "Inactive")
        target_page = self.client.get(self.page(self.medium))
        self.assertContains(target_page, "Downgrade paths")
        self.assertContains(target_page, "Small")
        detail = self.client.get(reverse("products:product_detail", kwargs={"slug": self.small.slug}))
        self.assertContains(detail, self.page())

    def test_support_can_inspect_but_admin_mutations_are_denied(self) -> None:
        edge = self.edge()
        self.client.force_login(self.support)
        response = self.client.get(self.page())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Only administrators can change the product catalog.")
        controls = [attrs.get("href", "") for _, attrs in Markup(response.content.decode()).elements]
        self.assertNotIn(self.page() + "create/", controls)
        for url in (self.page() + "create/", self.page() + f"{edge.pk}/edit/", self.page() + f"{edge.pk}/remove/"):
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url, {"target_product": self.large.pk}).status_code, 403)
        edge.refresh_from_db()
        self.assertEqual(edge.target_product_id, self.medium.pk)

    def test_catalog_policy_does_not_promote_billing_manager_or_django_staff(self) -> None:
        for role in ("billing", "manager", ""):
            user = User.objects.create_user(
                email=f"graph-{role or 'staff'}@example.com", staff_role=role, is_staff=True
            )
            self.client.force_login(user)
            self.assertEqual(self.create().status_code, 403)
        self.assertFalse(ProductRelationship.objects.exists())
        superuser = User.objects.create_superuser(email="graph-superuser@example.com", password="fixture")
        self.client.force_login(superuser)
        self.assertEqual(self.create().status_code, 302)

    def test_self_duplicate_opposite_and_longer_cycle_refuse_without_mutation(self) -> None:
        response = self.create(self.small)
        self.assertContains(response, "itself", status_code=400)
        self.assertFalse(ProductRelationship.objects.exists())
        self.edge()
        response = self.create()
        self.assertContains(response, "already exists", status_code=400)
        response = self.create(self.small, source=self.medium)
        self.assertContains(response, "opposite direction", status_code=400)
        self.edge(source=self.medium, target=self.large)
        response = self.create(self.small, source=self.large)
        self.assertContains(response, "cycle", status_code=400)
        self.assertEqual(ProductRelationship.objects.count(), 2)

    def test_inactive_edge_activation_rechecks_current_graph(self) -> None:
        self.edge()
        dormant = self.edge(source=self.medium, target=self.small, is_active=False)
        response = self.client.post(
            self.page(self.medium) + f"{dormant.pk}/edit/",
            {"target_product": self.small.pk, "is_active": "on", "sort_order": 0},
        )
        self.assertContains(response, "opposite direction", status_code=400)
        dormant.refresh_from_db()
        self.assertFalse(dormant.is_active)

    def test_foreign_source_and_other_relationship_type_cannot_be_edited_or_removed(self) -> None:
        foreign = self.edge(source=self.medium, target=self.large)
        unrelated = ProductRelationship.objects.create(
            source_product=self.small, target_product=self.medium, relationship_type="requires"
        )
        for edge in (foreign, unrelated):
            for action in ("edit", "remove"):
                with self.subTest(edge=edge.pk, action=action):
                    response = self.client.post(self.page() + f"{edge.pk}/{action}/", {"target_product": self.large.pk})
                    self.assertEqual(response.status_code, 404)
        self.assertEqual(ProductRelationship.objects.count(), 2)

    def test_remove_is_post_only_and_real_form_supplies_csrf(self) -> None:
        edge = self.edge()
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        response = strict.get(self.page() + "create/")
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        self.assertEqual(strict.post(self.page() + "create/", {"target_product": self.large.pk}).status_code, 403)
        response = strict.post(
            self.page() + "create/",
            {"target_product": self.large.pk, "is_active": "on", "sort_order": 0},
            HTTP_X_CSRFTOKEN=body_csrf_token(response.content.decode()),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(strict.get(self.page() + f"{edge.pk}/remove/").status_code, 405)

    def test_customer_and_anonymous_cannot_inspect_staff_graph(self) -> None:
        self.client.logout()
        self.assertEqual(self.client.get(self.page()).status_code, 302)
        customer = User.objects.create_user(email="upgrade-catalog-customer@example.com")
        self.client.force_login(customer)
        self.assertEqual(self.client.get(self.page()).status_code, 403)
