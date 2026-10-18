"""An audit event names who acted, not the person the change was made to (rows 36, 41, 53, 55)."""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.audit.actor_context import acting_as
from apps.audit.models import AuditEvent, audit_mutation_allowed
from apps.audit.services import AuditContext, CustomersAuditService, _with_user, actor_context
from apps.customers.models import Customer, CustomerNote
from apps.users.mfa import TOTPService
from apps.users.models import CustomerMembership, User, UserProfile

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


def events(action: str) -> list[AuditEvent]:
    return list(AuditEvent.objects.filter(action=action).order_by("timestamp"))


def forget_events() -> None:
    with audit_mutation_allowed("test fixture"):
        AuditEvent.objects.all().delete()


class UserChangeAttributionTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(email="attr-admin@example.com", password=PASSWORD, staff_role="admin")
        self.subject = User.objects.create_user(
            email="attr-subject@example.com",
            password=PASSWORD,
            staff_role="support",
            first_name="Ana",
            last_name="Pop",
            phone="+40700000001",
        )
        forget_events()

    def test_staff_role_change_credits_the_admin_not_the_subject(self) -> None:
        with acting_as(self.admin):
            self.subject.staff_role = "billing"
            self.subject.save(update_fields=["staff_role"])

        (event,) = events("staff_role_changed")
        self.assertEqual(event.user, self.admin)
        self.assertEqual(event.actor_type, "user")
        self.assertEqual(event.content_object, self.subject)
        self.assertEqual(event.old_values, {"staff_role": "support"})
        self.assertEqual(event.new_values, {"staff_role": "billing"})

    def test_a_change_nobody_made_is_credited_to_the_system(self) -> None:
        self.subject.staff_role = "billing"
        self.subject.save(update_fields=["staff_role"])

        (event,) = events("staff_role_changed")
        self.assertIsNone(event.user)
        self.assertEqual(event.actor_type, "system")
        self.assertEqual(event.content_object, self.subject)

    def test_a_change_to_both_names_emits_one_name_changed(self) -> None:
        with acting_as(self.admin):
            self.subject.first_name = "Maria"
            self.subject.last_name = "Ionescu"
            self.subject.save(update_fields=["first_name", "last_name"])

        (event,) = events("name_changed")
        self.assertEqual(event.old_values, {"first_name": "Ana", "last_name": "Pop"})
        self.assertEqual(event.new_values, {"first_name": "Maria", "last_name": "Ionescu"})

    def test_a_full_save_detects_the_changed_fields(self) -> None:
        with acting_as(self.admin):
            self.subject.email = "attr-subject-new@example.com"
            self.subject.phone = "+40700000002"
            self.subject.save()

        self.assertEqual([e.old_values for e in events("email_changed")], [{"email": "attr-subject@example.com"}])
        self.assertEqual([e.new_values for e in events("phone_updated")], [{"phone": "+40700000002"}])
        self.assertEqual(events("name_changed"), [])
        self.assertEqual(events("staff_role_changed"), [])
        self.assertEqual(events("profile_updated"), [])

    def test_an_unchanged_update_fields_save_emits_nothing(self) -> None:
        with acting_as(self.admin):
            self.subject.save(update_fields=["staff_role", "email", "first_name"])
            self.subject.save()

        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_only_the_fields_in_update_fields_are_audited(self) -> None:
        with acting_as(self.admin):
            self.subject.phone = "+40700000009"
            self.subject.staff_role = "billing"
            self.subject.save(update_fields=["phone"])

        self.assertEqual(len(events("phone_updated")), 1)
        self.assertEqual(events("staff_role_changed"), [])

    def test_every_save_is_compared_with_the_row_as_it_is_then(self) -> None:
        with acting_as(self.admin):
            self.subject.phone = "+40700000003"
            self.subject.save()
            self.subject.phone = "+40700000004"
            self.subject.save()

        self.assertEqual(
            [(e.old_values, e.new_values) for e in events("phone_updated")],
            [
                ({"phone": "+40700000001"}, {"phone": "+40700000003"}),
                ({"phone": "+40700000003"}, {"phone": "+40700000004"}),
            ],
        )

    def test_a_deferred_field_is_not_compared(self) -> None:
        with acting_as(self.admin):
            deferred = User.objects.only("id", "email").get(pk=self.subject.pk)
            deferred.email = "attr-deferred@example.com"
            deferred.save(update_fields=["email"])

        self.assertEqual([e.new_values for e in events("email_changed")], [{"email": "attr-deferred@example.com"}])
        self.assertEqual(events("phone_updated"), [])

    def test_an_administrator_resetting_2fa_is_the_actor_of_every_event_end_to_end(self) -> None:
        for user in (self.admin, self.subject):
            user.two_factor_secret = TOTPService.generate_secret()
            user.two_factor_enabled = True
            user.save()
        forget_events()

        self.client.force_login(self.admin)
        self.client.post(reverse("users:mfa_admin_reset", kwargs={"pk": self.subject.pk}))

        about_subject = AuditEvent.objects.filter(object_id=str(self.subject.pk), action__startswith="2fa_")
        self.assertTrue(about_subject.exists())
        self.assertEqual({e.user for e in about_subject}, {self.admin})


class ProfileAndMembershipAttributionTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(email="attr2-admin@example.com", password=PASSWORD, staff_role="admin")
        self.subject = User.objects.create_user(email="attr2-subject@example.com", password=PASSWORD)
        self.customer = Customer.objects.create(company_name="Attr Co", customer_type="business", status="active")
        self.membership = CustomerMembership.objects.create(user=self.subject, customer=self.customer, role="viewer")
        self.profile, _created = UserProfile.objects.get_or_create(user=self.subject)
        forget_events()

    def test_a_profile_preference_change_credits_the_actor(self) -> None:
        with acting_as(self.admin):
            self.profile.timezone = "Europe/Bucharest" if self.profile.timezone != "Europe/Bucharest" else "UTC"
            self.profile.save()

        (event,) = events("timezone_changed")
        self.assertEqual((event.user, event.content_object), (self.admin, self.profile))
        self.assertEqual(set(event.old_values), {"timezone"})

    def test_a_membership_role_change_credits_the_actor_and_keeps_the_old_role(self) -> None:
        with acting_as(self.admin):
            self.membership.role = "owner"
            self.membership.save()

        (event,) = events("customer_role_changed")
        self.assertEqual((event.user, event.content_object), (self.admin, self.membership))
        self.assertEqual(event.old_values, {"role": "viewer"})
        self.assertEqual(event.new_values, {"role": "owner"})

    def test_a_membership_save_that_changes_nothing_emits_nothing(self) -> None:
        with acting_as(self.admin):
            self.membership.save()
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_removing_a_membership_credits_the_actor(self) -> None:
        with acting_as(self.admin):
            self.membership.delete()

        (event,) = events("customer_membership_deleted")
        self.assertEqual(event.user, self.admin)

    def test_customer_row_changes_credit_the_actor(self) -> None:
        with acting_as(self.admin):
            self.customer.company_name = "Attr Renamed Co"
            self.customer.save()
        (updated,) = events("customer_updated")
        self.assertEqual((updated.user, updated.actor_type), (self.admin, "user"))

        forget_events()
        self.customer.company_name = "Attr Renamed Again Co"
        self.customer.save()
        (by_system,) = events("customer_updated")
        self.assertEqual((by_system.user, by_system.actor_type), (None, "system"))

    def test_actor_context_names_the_actor_or_the_system(self) -> None:
        with acting_as(self.admin):
            context = actor_context()
        self.assertEqual((context.user, context.actor_type), (self.admin, "user"))
        self.assertEqual((actor_context().user, actor_context().actor_type), (None, "system"))


class HelperUserTests(TestCase):
    def setUp(self) -> None:
        self.author = User.objects.create_user(email="note-author@example.com", password=PASSWORD, staff_role="support")
        self.other = User.objects.create_user(email="note-other@example.com", password=PASSWORD, staff_role="admin")
        self.customer = Customer.objects.create(company_name="Note Co", customer_type="business", status="active")
        forget_events()

    def test_note_event_keeps_its_author(self) -> None:
        CustomerNote.objects.create(
            customer=self.customer, title="Call", content="Spoke to them", created_by=self.author
        )

        (event,) = events("customer_note_created")
        self.assertEqual(event.user, self.author)

    def test_a_helper_given_a_user_and_a_context_writes_the_user(self) -> None:
        note = CustomerNote.objects.create(customer=self.customer, title="T", content="C", created_by=self.author)
        forget_events()

        CustomersAuditService.log_note_event(
            event_type="customer_note_updated",
            note=note,
            user=self.author,
            context=AuditContext(ip_address="203.0.113.7"),
        )

        (event,) = events("customer_note_updated")
        self.assertEqual(event.user, self.author)
        self.assertEqual(str(event.ip_address), "203.0.113.7")

    def test_with_user_never_changes_the_callers_context(self) -> None:
        context = AuditContext(ip_address="203.0.113.7")
        result = _with_user(context, self.author)

        self.assertIsNone(context.user)
        self.assertEqual(result.user, self.author)
        self.assertEqual(result.ip_address, "203.0.113.7")
        self.assertIs(_with_user(result, None), result)
        self.assertIs(_with_user(result, self.author), result)

    def test_no_helper_ignores_the_user_it_was_given(self) -> None:
        """Every helper that takes both a user and a context goes through ``_with_user``."""
        import inspect  # noqa: PLC0415

        from apps.audit import services  # noqa: PLC0415

        source = inspect.getsource(services)
        self.assertNotIn("if context is None:\n            context = AuditContext(user=user)", source)
        self.assertNotIn("if event_data.context is None:", source)
