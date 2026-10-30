"""Staff change a customer's lifecycle status from its page, within their role (ADR-0066).

Admins and managers may take every transition; support may suspend and unsuspend; billing staff and a
bare staff flag may take none. Every test drives the real view and the real FSM transition, and checks
the status the customer is left in, never only the response.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.users.models import User

# The status each action starts from, and the one it leads to.
ACTIONS = {
    "activate": ("prospect", "active"),
    "deactivate": ("active", "inactive"),
    "reactivate": ("inactive", "active"),
    "suspend": ("active", "suspended"),
    "unsuspend": ("suspended", "active"),
}
EVERY_ACTION = frozenset(ACTIONS)
ALLOWED_BY_ROLE = {
    "admin": EVERY_ACTION,
    "manager": EVERY_ACTION,
    "support": frozenset({"suspend", "unsuspend"}),
    "billing": frozenset(),
    "": frozenset(),  # a bare staff flag, no role
}


class CustomerStatusActionTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Lifecycle SRL", customer_type="company", primary_email="l@example.test")

    def _staff(self, role: str) -> User:
        user = User.objects.create_user(email=f"{role or 'bare'}-staff@example.test", password="x", is_staff=True)
        User.objects.filter(pk=user.pk).update(staff_role=role)
        user.refresh_from_db()
        self.client.force_login(user)
        return user

    def _set_status(self, status: str) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(status=status)
        self.assertEqual(Customer.objects.get(pk=self.customer.pk).status, status)

    def _post(self, action: str):
        return self.client.post(reverse("customers:status_change", args=[self.customer.pk, action]))

    def _status(self) -> str:
        return Customer.objects.get(pk=self.customer.pk).status

    def test_each_role_may_take_exactly_its_actions(self) -> None:
        for role, allowed in ALLOWED_BY_ROLE.items():
            staff = self._staff(role)
            for action, (source, target) in ACTIONS.items():
                with self.subTest(role=role or "bare staff", action=action):
                    self._set_status(source)
                    response = self._post(action)
                    if action in allowed:
                        self.assertEqual(response.status_code, 302)
                        self.assertEqual(self._status(), target)
                    else:
                        self.assertEqual(response.status_code, 403)
                        self.assertEqual(self._status(), source)
            self.client.logout()
            staff.delete()

    def test_a_transition_from_the_wrong_status_changes_nothing(self) -> None:
        self._staff("admin")
        self._set_status("prospect")
        response = self._post("unsuspend")  # only a suspended customer can be unsuspended
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._status(), "prospect")

    def test_an_unknown_action_is_not_found(self) -> None:
        self._staff("admin")
        self.assertEqual(self._post("delete").status_code, 404)

    def test_a_get_changes_nothing(self) -> None:
        self._staff("admin")
        self._set_status("active")
        response = self.client.get(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self._status(), "active")

    def test_the_change_is_audited_with_the_staff_member_and_both_statuses(self) -> None:
        staff = self._staff("manager")
        self._set_status("prospect")
        self._post("activate")
        event = AuditEvent.objects.filter(action="customer_updated", object_id=str(self.customer.pk)).latest("timestamp")
        self.assertEqual(event.user, staff)
        self.assertEqual((event.old_values.get("status"), event.new_values.get("status")), ("prospect", "active"))

    def test_the_page_offers_only_the_actions_the_role_and_status_allow(self) -> None:
        detail = reverse("customers:detail", args=[self.customer.pk])

        def offered() -> set[str]:
            page = self.client.get(detail).content.decode()
            return {action for action in ACTIONS if reverse("customers:status_change", args=[self.customer.pk, action]) in page}

        self._set_status("active")
        self._staff("admin")
        self.assertEqual(offered(), {"deactivate", "suspend"})
        self._staff("support")
        self.assertEqual(offered(), {"suspend"})
        self._staff("billing")
        self.assertEqual(offered(), set())
