"""Coverage additions for production Virtualmin forms."""

from __future__ import annotations

from typing import cast

from django import forms
from django.test import SimpleTestCase

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_forms import (
    VirtualminAccountForm,
    VirtualminBackupForm,
    VirtualminBulkActionForm,
    VirtualminRestoreForm,
    VirtualminServerForm,
)
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class VirtualminOperationFormTests(SimpleTestCase):
    def test_backup_requires_a_feature_and_preserves_the_selected_feature(self) -> None:
        empty = VirtualminBackupForm({"backup_type": "full"})
        self.assertFalse(empty.is_valid())
        self.assertIn("At least one feature must be included", str(empty.non_field_errors()))
        selected = VirtualminBackupForm({"backup_type": "config_only", "include_ssl": "on"})
        self.assertTrue(selected.is_valid(), selected.errors)
        self.assertEqual(selected.cleaned_data["backup_type"], "config_only")
        self.assertTrue(selected.cleaned_data["include_ssl"])
        self.assertFalse(selected.cleaned_data["include_files"])

    def test_restore_choices_confirmation_and_selected_features(self) -> None:
        backups: list[dict[str, object]] = [
            {"backup_id": "backup-42", "backup_type": "full", "created_at": "2026-10-07"}
        ]
        selected = VirtualminRestoreForm(
            {"backup_id": "backup-42", "restore_files": "on", "confirm_restore": "on"},
            available_backups=backups,
        )
        self.assertTrue(selected.is_valid(), selected.errors)
        self.assertEqual(selected.cleaned_data["backup_id"], "backup-42")
        self.assertTrue(selected.cleaned_data["restore_files"])
        self.assertFalse(selected.cleaned_data["force_restore"])
        field = cast(forms.ChoiceField, selected.fields["backup_id"])
        self.assertEqual(list(field.choices), [("backup-42", "backup-42 - Full (2026-10-07)")])

        no_features = VirtualminRestoreForm(
            {"backup_id": "backup-42", "confirm_restore": "on"}, available_backups=backups
        )
        self.assertFalse(no_features.is_valid())
        self.assertIn("At least one feature must be selected", str(no_features.non_field_errors()))
        no_confirmation = VirtualminRestoreForm(
            {"backup_id": "backup-42", "restore_files": "on"}, available_backups=backups
        )
        self.assertFalse(no_confirmation.is_valid())
        self.assertIn("confirm_restore", no_confirmation.errors)

    def test_restore_refuses_a_backup_outside_the_available_choices(self) -> None:
        form = VirtualminRestoreForm(
            {"backup_id": "missing", "restore_files": "on", "confirm_restore": "on"}, available_backups=[]
        )
        self.assertFalse(form.is_valid())
        self.assertIn("backup_id", form.errors)
        self.assertEqual(list(cast(forms.ChoiceField, form.fields["backup_id"]).choices), [])

    def test_bulk_action_refuses_empty_selection_and_missing_confirmation(self) -> None:
        for selection in ("", " , , "):
            form = VirtualminBulkActionForm(
                {"action": "suspend", "selected_accounts": selection, "confirm_bulk_action": "on"}
            )
            with self.subTest(selection=selection):
                self.assertFalse(form.is_valid())
                self.assertIn("selected_accounts", form.errors)
        form = VirtualminBulkActionForm({"action": "activate", "selected_accounts": "first"})
        self.assertFalse(form.is_valid())
        self.assertIn("confirm_bulk_action", form.errors)


class VirtualminModelFormTests(VirtualminViewsFixture):
    def test_bulk_action_accepts_account_lists_and_requires_backup_type(self) -> None:
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="second.example.com",
            domain="second.example.com",
            username="second",
            price=self.service.price,
            billing_cycle="monthly",
            status="active",
        )
        second = VirtualminAccount.objects.create(
            server=self.server, service=service, domain=service.domain, virtualmin_username="second", status="active"
        )
        ids = [str(self.account.pk), str(second.pk)]
        accounts = VirtualminAccount.objects.filter(pk__in=ids)
        selected = VirtualminBulkActionForm(
            {"action": "suspend", "selected_accounts": ids, "confirm_bulk_action": "on"}, accounts=accounts
        )
        self.assertTrue(selected.is_valid(), selected.errors)
        self.assertEqual(
            set(selected.cleaned_data["selected_accounts"].values_list("pk", flat=True)),
            {self.account.pk, second.pk},
        )
        self.assertIsInstance(selected.fields["selected_accounts"].widget, forms.CheckboxSelectMultiple)
        comma_separated = VirtualminBulkActionForm(
            {"action": "suspend", "selected_accounts": ",".join(ids), "confirm_bulk_action": "on"}, accounts=accounts
        )
        self.assertFalse(comma_separated.is_valid())
        self.assertIn("selected_accounts", comma_separated.errors)
        backup = VirtualminBulkActionForm(
            {"action": "backup", "selected_accounts": ids, "confirm_bulk_action": "on"}, accounts=accounts
        )
        self.assertFalse(backup.is_valid())
        self.assertIn("Backup type is required", str(backup.non_field_errors()))
        complete_backup = VirtualminBulkActionForm(
            {"action": "backup", "selected_accounts": ids, "confirm_bulk_action": "on", "backup_type": "full"},
            accounts=accounts,
        )
        self.assertTrue(complete_backup.is_valid(), complete_backup.errors)
        self.assertEqual(complete_backup.cleaned_data["backup_type"], "full")
        self.assertEqual(
            set(complete_backup.cleaned_data["selected_accounts"].values_list("pk", flat=True)),
            {self.account.pk, second.pk},
        )

    def test_server_form_reports_invalid_hostname_username_and_password(self) -> None:
        cases = (
            ("hostname", "bad/host", "Invalid hostname format"),
            ("api_username", "bad user", "Invalid username format"),
            ("api_password", "weak", "Password validation failed"),
        )
        for field, value, error in cases:
            data = self.server_data()
            data[field] = value
            form = VirtualminServerForm(data)
            with self.subTest(field=field):
                self.assertFalse(form.is_valid())
                self.assertIn(error, str(form.errors[field]))
                self.assertFalse(VirtualminServer.objects.filter(hostname=data["hostname"]).exists())

    def test_server_form_normalizes_pin_and_encrypts_before_deferred_save(self) -> None:
        data = self.server_data()
        data.pop("ssl_verify")
        data["ssl_cert_fingerprint"] = ":".join(["AB"] * 32)
        form = VirtualminServerForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        server = form.save(commit=False)
        self.assertFalse(VirtualminServer.objects.filter(pk=server.pk).exists())
        self.assertEqual(server.ssl_cert_fingerprint, "ab" * 32)
        self.assertEqual(server.get_api_password(), data["api_password"])
        self.assertNotEqual(server.encrypted_api_password, data["api_password"].encode())
        server.save()
        saved = VirtualminServer.objects.get(pk=server.pk)
        self.assertEqual(saved.get_api_password(), data["api_password"])
        self.assertFalse(saved.ssl_verify)

    def test_editing_server_without_password_preserves_its_encrypted_credential(self) -> None:
        data = self.server_data()
        data.update(name=self.server.name, hostname=self.server.hostname, api_password="")
        original = bytes(self.server.encrypted_api_password)
        form = VirtualminServerForm(data, instance=self.server)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        saved = VirtualminServer.objects.get(pk=self.server.pk)
        self.assertEqual(bytes(saved.encrypted_api_password), original)
        self.assertEqual(saved.get_api_password(), "test_password")

    def test_server_form_refuses_http_missing_pin_and_invalid_pin(self) -> None:
        for change, field in (
            ({"use_ssl": "", "ssl_verify": "on"}, "use_ssl"),
            ({"ssl_verify": "", "ssl_cert_fingerprint": ""}, "ssl_cert_fingerprint"),
            ({"ssl_verify": "", "ssl_cert_fingerprint": "invalid"}, "ssl_cert_fingerprint"),
        ):
            data = self.server_data()
            data.update(change)
            form = VirtualminServerForm(data)
            with self.subTest(change=change):
                self.assertFalse(form.is_valid())
                self.assertIn(field, form.errors)
                self.assertFalse(VirtualminServer.objects.filter(hostname=data["hostname"]).exists())

    def test_account_form_excludes_inactive_servers_and_sets_quota_defaults(self) -> None:
        offline = VirtualminServer.objects.create(
            name="Support offline", hostname="support-offline.example.com", status="disabled"
        )
        form = VirtualminAccountForm()
        servers = cast("forms.ModelChoiceField[VirtualminServer]", form.fields["server"]).queryset
        self.assertIsNotNone(servers)
        assert servers is not None
        self.assertIn(self.server, servers)
        self.assertNotIn(offline, servers)
        self.assertEqual(form.fields["disk_quota_mb"].initial, 1000)
        self.assertEqual(form.fields["bandwidth_quota_mb"].initial, 10000)
        self.assertTrue(form.fields["virtualmin_username"].required)

    def test_account_form_refuses_duplicate_and_malformed_domains(self) -> None:
        self.account.domain = "duplicate.example"
        self.account.save(update_fields=["domain"])
        for domain, error in (
            (" DUPLICATE.EXAMPLE ", "An account with this domain already exists"),
            ("bad/domain", "Invalid domain name format"),
        ):
            form = VirtualminAccountForm(
                {
                    "domain": domain,
                    "server": str(self.server.pk),
                    "service": str(self.service.pk),
                    "virtualmin_username": "newtenant",
                    "status": "active",
                }
            )
            with self.subTest(domain=domain):
                self.assertFalse(form.is_valid())
                self.assertIn(error, str(form.errors["domain"]))
