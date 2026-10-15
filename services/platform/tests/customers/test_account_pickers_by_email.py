"""Linking an account to a customer names it by exact email, never from a list of every account (#689).

The user list became administrator-only because it lists every account, staff and customers
alike. Three customer pages showed the same list, to every staff role, as a dropdown.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.customers.forms import CustomerUserAssignmentForm
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

PASSWORD = "x-pass-123"  # test fixture, not a credential


class AccountPickersByEmailTests(TestCase):
    def setUp(self) -> None:
        self.support = User.objects.create_user(
            email="support@example.com", password=PASSWORD, is_staff=True, staff_role="support"
        )
        self.bystander = User.objects.create_user(email="bystander@example.com", password=PASSWORD)
        self.colleague = User.objects.create_user(
            email="colleague@example.com", password=PASSWORD, is_staff=True, staff_role="billing"
        )
        self.customer = Customer.objects.create(
            name="Acme", company_name="Acme SRL", primary_email="office@acme.example", customer_type="company"
        )
        self.client.force_login(self.support)

    def test_no_page_lists_other_accounts(self) -> None:
        pages = {
            "add user": reverse("customers:add_user", args=[self.customer.id]),
            "assign user": reverse("customers:assign_user", args=[self.customer.id]),
            "create customer": reverse("customers:create"),
        }
        for name, url in pages.items():
            with self.subTest(page=name):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, self.bystander.email)
                self.assertNotContains(response, self.colleague.email)

    def test_add_user_links_an_account_by_its_exact_email(self) -> None:
        response = self.client.post(
            reverse("customers:add_user", args=[self.customer.id]),
            {"user_email": "Bystander@Example.com", "role": "viewer"},
        )
        self.assertRedirects(
            response, reverse("customers:detail", args=[self.customer.id]), fetch_redirect_response=False
        )
        self.assertTrue(CustomerMembership.objects.filter(customer=self.customer, user=self.bystander).exists())

    def test_add_user_refuses_a_deactivated_account(self) -> None:
        self.bystander.is_active = False
        self.bystander.save(update_fields=["is_active"])
        self.client.post(
            reverse("customers:add_user", args=[self.customer.id]),
            {"user_email": self.bystander.email, "role": "viewer"},
        )
        self.assertFalse(CustomerMembership.objects.filter(customer=self.customer, user=self.bystander).exists())

    def test_the_assignment_form_resolves_an_email_to_the_account(self) -> None:
        form = CustomerUserAssignmentForm(
            customer=self.customer,
            data={"user_action": "link", "existing_user": "bystander@example.com", "role": "viewer"},
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["existing_user"], self.bystander)

    def test_the_assignment_form_refuses_unknown_and_existing_members(self) -> None:
        CustomerMembership.objects.create(customer=self.customer, user=self.bystander, role="viewer")
        for email in ("nobody@example.com", "bystander@example.com"):
            with self.subTest(email=email):
                form = CustomerUserAssignmentForm(
                    customer=self.customer, data={"user_action": "link", "existing_user": email, "role": "viewer"}
                )
                self.assertFalse(form.is_valid())
                self.assertIn("existing_user", form.errors)
