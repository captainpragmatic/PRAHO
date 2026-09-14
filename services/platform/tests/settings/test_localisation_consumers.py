"""Settings must change real pages, forms and profile persistence."""

from datetime import UTC, datetime
from unittest.mock import patch

from django.core.cache import cache
from django.template import Context, Template
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.translation import override

from apps.common.localisation_services import get_localisation_defaults, get_request_localisation
from apps.customers.forms import CustomerAddressForm, CustomerCreationForm, CustomerEditForm
from apps.customers.models import CustomerAddress
from apps.settings.catalog import defs_for_group
from apps.settings.services import SettingsService
from apps.users.models import UserProfile
from tests.factories.core_factories import create_full_customer, create_staff_user


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class LocalisationConsumerTests(TestCase):
    def setUp(self) -> None:
        self.enterContext(override("en"))
        cache.clear()
        self.addCleanup(cache.clear)
        self.staff = create_staff_user(username="localisation_staff", staff_role="support")

    def set_value(self, key: str, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_setting_changes_rendered_date_and_next_request(self) -> None:
        self.set_value("system.staff_date_format", "%Y-%m-%d")
        self.set_value("system.timezone", "UTC")
        request = RequestFactory().get("/")
        request.user = self.staff
        template = Template('{% load localisation_tags %}{% localised_date instant "datetime" %}')
        context = Context({"request": request, "instant": datetime(2025, 12, 31, 22, 30, tzinfo=UTC)})
        self.assertEqual(template.render(context), "2025-12-31 22:30")
        self.set_value("system.timezone", "Europe/Bucharest")
        self.assertEqual(template.render(context), "2025-12-31 22:30")
        other = RequestFactory().get("/")
        other.user = self.staff
        context["request"] = other
        self.assertEqual(template.render(context), "2026-01-01 00:30")

    def test_many_dates_resolve_settings_once(self) -> None:
        request = RequestFactory().get("/")
        request.user = self.staff
        with patch(
            "apps.common.localisation_services.get_localisation_defaults", wraps=get_localisation_defaults
        ) as reader:
            for _ in range(20):
                get_request_localisation(request)
        reader.assert_called_once()

    def test_country_default_reaches_new_forms_and_preserves_initials(self) -> None:
        self.set_value("system.default_country", "DE")
        self.assertEqual(CustomerCreationForm().initial["country"], "Germany")
        self.assertEqual(CustomerAddressForm().initial["country"], "Germany")
        self.assertEqual(CustomerAddressForm(initial={"country": "France"}).initial["country"], "France")
        bound = CustomerAddressForm(data={"country": "Italy"})
        self.assertEqual(bound["country"].value(), "Italy")

    def test_country_labels_and_new_form_defaults_follow_each_request_language(self):
        self.set_value("system.default_country", "DE")
        definition = next(item for item in defs_for_group("localisation") if item.key == "system.default_country")
        label = definition.choice_labels["DE"]
        for language, expected in (("en", "Germany"), ("ro", "Germania"), ("en", "Germany")):
            with override(language):
                self.assertEqual(str(label), expected)
                self.assertEqual(CustomerCreationForm()["country"].value(), expected)

    def test_country_does_not_replace_existing_address(self) -> None:
        self.set_value("system.default_country", "DE")
        address = CustomerAddress(pk=42, country="France")
        self.assertEqual(CustomerAddressForm(instance=address)["country"].value(), "France")

    def test_customer_edit_preserves_saved_primary_and_billing_countries(self):
        self.set_value("system.default_country", "DE")
        customer = create_full_customer()
        address = customer.get_primary_address()
        address.country = "France"
        address.save(update_fields=["country"])
        CustomerAddress.objects.create(
            customer=customer, is_billing=True, is_primary=False, country="Italy",
            address_line1="Example 1", city="Rome", county="Rome", postal_code="00100",
        )
        form = CustomerEditForm(customer)
        self.assertEqual(form["country"].value(), "France")
        self.assertEqual(form["billing_country"].value(), "Italy")
        explicit = CustomerEditForm(customer, initial={"country": "Spain"})
        self.assertEqual(explicit["country"].value(), "Spain")

    def test_gdpr_list_dates_use_the_http_request_preferences(self):
        self.set_value("system.timezone", "Europe/Bucharest")
        self.staff.profile.timezone = "UTC"
        self.staff.profile.date_format = "%Y-%m-%d"
        self.staff.profile.save()
        request = RequestFactory().get("/")
        request.user = self.staff
        rendered = render_to_string(
            "audit/partials/gdpr_export_requests_list.html",
            {"export_requests": [{"id": "00000000-0000-0000-0000-000000000001", "status": "processing",
                                  "requested_at": datetime(2025, 12, 31, 22, 30, tzinfo=UTC)}]},
            request=request,
        )
        self.assertIn('title="2025-12-31 22:30:00"', rendered)

    def test_default_country_and_override_reach_persisted_customer(self):
        self.set_value("system.default_country", "DE")
        data = {
            "user_action": "create",
            "first_name": "Country",
            "last_name": "Test",
            "email": "country@example.test",
            "phone": "+40.21.123.4567",
            "customer_type": "company",
            "company_name": "Country Test SRL",
            "address_line1": "Example 1",
            "city": "Berlin",
            "county": "Berlin",
            "postal_code": "10115",
            "payment_terms": 30,
            "credit_limit": 0,
            "preferred_currency": "RON",
            "data_processing_consent": True,
        }
        for extra, expected in (({}, "Germany"), ({"country": "France"}, "France")):
            form = CustomerCreationForm(data={**data, **extra})
            self.assertTrue(form.is_valid(), form.errors)
            customer = form.save(user=self.staff)["customer"]
            self.assertEqual(customer.get_primary_address().country, expected)

    def test_postal_validation_uses_actual_country_after_all_fields_are_cleaned(self):
        common = {"address_line1": "Example 1", "city": "Berlin", "county": "Berlin", "postal_code": "10115"}
        german = CustomerAddressForm(data={**common, "country": "DE"})
        romanian = CustomerAddressForm(data={**common, "country": "RO"})
        german.is_valid()
        romanian.is_valid()
        self.assertNotIn("postal_code", german.errors)
        self.assertIn("postal_code", romanian.errors)

    def test_profile_combined_save_and_inheritance(self) -> None:
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("users:user_profile"),
            {
                "first_name": "Updated",
                "last_name": "Person",
                "phone": "",
                "preferred_language": "ro",
                "timezone": "UTC",
                "date_format": "%Y-%m-%d",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.staff.refresh_from_db()
        profile = UserProfile.objects.get(user=self.staff)
        self.assertEqual(
            (self.staff.first_name, profile.preferred_language, profile.timezone, profile.date_format),
            ("Updated", "ro", "UTC", "%Y-%m-%d"),
        )
        response = self.client.post(
            reverse("users:user_profile"), {"preferred_language": "", "timezone": "", "date_format": ""}
        )
        self.assertEqual(response.status_code, 302)
        profile.refresh_from_db()
        self.assertEqual((profile.preferred_language, profile.timezone, profile.date_format), ("", "", ""))
        self.assertTrue(profile.email_notifications)

    def test_staff_profile_preserves_preferences_not_rendered_on_the_page(self):
        profile = self.staff.profile
        profile.email_notifications = True
        profile.sms_notifications = True
        profile.marketing_emails = True
        profile.save()
        self.client.force_login(self.staff)
        response = self.client.get(reverse("users:user_profile"))
        for field in ("email_notifications", "sms_notifications", "marketing_emails"):
            self.assertNotContains(response, f'name="{field}"')
        self.assertEqual(self.client.post(reverse("users:user_profile"), {"timezone": "UTC"}).status_code, 302)
        profile.refresh_from_db()
        self.assertTrue(profile.email_notifications)
        self.assertTrue(profile.sms_notifications)
        self.assertTrue(profile.marketing_emails)

    def test_invalid_profile_does_not_partially_save(self) -> None:
        self.client.force_login(self.staff)
        previous = self.staff.first_name
        response = self.client.post(reverse("users:user_profile"), {"first_name": "Changed", "timezone": "invalid"})
        self.assertEqual(response.status_code, 200)
        self.staff.refresh_from_db()
        self.assertEqual(self.staff.first_name, previous)

    def test_language_setting_changes_real_staff_page(self) -> None:
        self.set_value("system.default_language", "ro")
        self.client.force_login(self.staff)
        response = self.client.get(reverse("users:user_profile"))
        self.assertEqual(response["Content-Language"], "ro")
        self.assertContains(response, 'lang="ro"')
        self.assertContains(response, "Fus Orar")

    def test_catalog_rejects_invalid_values(self) -> None:
        for key, value in (
            ("system.default_language", "fr"),
            ("system.default_country", "ZZ"),
            ("system.timezone", "Etc/Bad"),
            ("system.staff_date_format", "%c"),
            ("system.customer_date_format", "%n"),
        ):
            self.assertTrue(SettingsService.update_setting(key, value).is_err())
