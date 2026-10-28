"""Secrets are bound to the natural key that finds them, not only to their row (#751 follow-up, M19).

The vault found a credential by (service_type, service_identifier) and the servers' API passwords belong to a
hostname, but the ciphertext was bound only to the row. A database writer who renamed a row redirected its
secret: get_credential("virtualmin", "B") returned what was stored for A, and a node renamed to a host the
writer controls sent its password there. The natural key is now part of the AAD: a raw rename leaves the
secret unreadable, an ORM rename re-wraps it, and a bulk write of a natural-key field is refused.
"""

from __future__ import annotations

from typing import Any

from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from apps.common.credential_vault import CredentialData, EncryptedCredential, get_credential_vault
from apps.common.encryption import DecryptionError
from apps.common.types import Result
from apps.provisioning.service_models import Server
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


def _store(identifier: str, value: str = "stored-secret") -> EncryptedCredential:
    get_credential_vault().store_credential(
        CredentialData(service_type="virtualmin", service_identifier=identifier, username="user", password=value)
    ).unwrap()
    return EncryptedCredential.objects.get(service_type="virtualmin", service_identifier=identifier)


def _read(identifier: str) -> Result[tuple[str, str, dict[str, Any] | None], str]:
    return get_credential_vault().get_credential("virtualmin", identifier, user=None, reason="test")


class VaultNaturalKeyTests(TestCase):
    def test_a_credential_renamed_in_the_database_is_not_readable_under_its_new_name(self) -> None:
        row = _store("node-a.example.com")
        EncryptedCredential._base_manager.filter(pk=row.pk).update(service_identifier="node-b.example.com")
        result = _read("node-b.example.com")
        self.assertTrue(result.is_err(), "A's secret must not be served as B's")

    def test_swapped_identifiers_serve_neither_secret(self) -> None:
        a, b = _store("a.example.com", "secret-a"), _store("b.example.com", "secret-b")
        manager = EncryptedCredential._base_manager
        manager.filter(pk=a.pk).update(service_identifier="swap.example.com")
        manager.filter(pk=b.pk).update(service_identifier="a.example.com")
        manager.filter(pk=a.pk).update(service_identifier="b.example.com")
        self.assertTrue(_read("a.example.com").is_err())
        self.assertTrue(_read("b.example.com").is_err())

    def test_a_stored_credential_still_reads(self) -> None:
        _store("node.example.com", "kept")
        self.assertEqual(_read("node.example.com").unwrap()[1], "kept")

    def test_an_orm_rename_is_refused_rather_than_leaving_the_secret_unreadable(self) -> None:
        row = _store("named.example.com", "kept")
        row.service_identifier = "renamed.example.com"
        with self.assertRaisesRegex(ValueError, "never renamed"):
            row.save()
        self.assertEqual(_read("named.example.com").unwrap()[1], "kept")

    def test_a_rename_after_a_deferred_load_is_refused(self) -> None:
        _store("deferred.example.com", "kept")
        row = EncryptedCredential.objects.only("id", "service_type", "service_identifier").get(
            service_identifier="deferred.example.com"
        )
        row.service_identifier = "renamed.example.com"
        with self.assertRaisesRegex(ValueError, "never renamed"):
            row.save()

    def test_a_rename_kept_across_a_partial_save_is_refused_on_the_full_save(self) -> None:
        row = _store("partial.example.com", "kept")
        row = EncryptedCredential.objects.get(pk=row.pk)
        row.service_identifier = "renamed.example.com"
        row.save(update_fields=["last_accessed"])
        with self.assertRaisesRegex(ValueError, "never renamed"):
            row.save()
        self.assertEqual(_read("partial.example.com").unwrap()[1], "kept")

    def test_a_rename_after_a_load_that_deferred_the_identifier_is_refused(self) -> None:
        _store("unloaded.example.com", "kept")
        row = EncryptedCredential.objects.only("id", "service_type").get(service_identifier="unloaded.example.com")
        row.service_identifier = "renamed.example.com"
        with self.assertRaisesRegex(ValueError, "never renamed"):
            row.save(update_fields=["service_identifier"])
        self.assertEqual(_read("unloaded.example.com").unwrap()[1], "kept")

    def test_a_rename_kept_across_a_partial_refresh_is_refused(self) -> None:
        row = EncryptedCredential.objects.get(pk=_store("refresh.example.com", "kept").pk)
        row.service_identifier = "renamed.example.com"
        row.refresh_from_db(fields=["service_type"])
        with self.assertRaisesRegex(ValueError, "never renamed"):
            row.save()

    def test_bulk_writes_of_the_natural_key_are_refused(self) -> None:
        row = _store("bulk.example.com")
        with self.assertRaisesRegex(ValueError, "natural key"):
            EncryptedCredential.objects.filter(pk=row.pk).update(service_identifier="other.example.com")
        with self.assertRaisesRegex(ValueError, "natural key"):
            EncryptedCredential.objects.filter(pk=row.pk).update(service_type="ssh")
        row.service_identifier = "other.example.com"
        with self.assertRaisesRegex(ValueError, "natural key"):
            EncryptedCredential.objects.bulk_update([row], ["service_identifier"])
        EncryptedCredential.objects.filter(pk=row.pk).update(is_active=True)  # Other fields still update


def _server(hostname: str = "node-old.example.com", value: str = "P1") -> VirtualminServer:
    server = VirtualminServer.objects.create(name=hostname, hostname=hostname, api_username="praho-acl")
    if value:
        server.set_api_password(value)
        server.save()
    return server


def _fresh(server: VirtualminServer) -> VirtualminServer:
    return VirtualminServer.objects.get(pk=server.pk)


class VirtualminServerHostnameTests(TestCase):
    def test_a_hostname_changed_in_the_database_leaves_the_password_unreadable(self) -> None:
        server = _server()
        VirtualminServer._base_manager.filter(pk=server.pk).update(hostname="attacker.example.net")
        with self.assertRaises(DecryptionError):
            _fresh(server).get_api_password()

    def test_a_full_save_rename_rewraps_the_password(self) -> None:
        server = _server()
        before = bytes(_fresh(server).encrypted_api_password)
        server.hostname = "node-new.example.com"
        server.save()
        stored = _fresh(server)
        self.assertEqual(stored.get_api_password(), "P1")
        self.assertNotEqual(bytes(stored.encrypted_api_password), before)

    def test_an_update_fields_rename_rewraps_the_password(self) -> None:
        server = _fresh(_server())
        server.hostname = "node-new.example.com"
        server.save(update_fields=["hostname", "updated_at"])
        self.assertEqual(_fresh(server).get_api_password(), "P1")

    def test_a_stale_instance_rename_keeps_the_newer_password(self) -> None:
        server = _server()
        stale, other = _fresh(server), _fresh(server)
        other.set_api_password("P2")
        other.save()
        stale.hostname = "node-new.example.com"
        stale.save()
        stored = _fresh(server)
        self.assertEqual(stored.hostname, "node-new.example.com")
        self.assertEqual(stored.get_api_password(), "P2")

    def test_a_rename_from_an_instance_loaded_without_a_password_rewraps_the_stored_one(self) -> None:
        server = _server(value="")
        stale, other = _fresh(server), _fresh(server)
        other.set_api_password("P2")
        other.save()
        stale.hostname = "node-new.example.com"
        stale.save(update_fields=["hostname"])
        self.assertEqual(_fresh(server).get_api_password(), "P2")

    def test_a_save_that_does_not_write_the_hostname_leaves_the_password_alone(self) -> None:
        server = _fresh(_server())
        server.hostname = "node-new.example.com"
        server.status = "maintenance"
        server.save(update_fields=["status"])
        stored = _fresh(server)
        self.assertEqual(stored.hostname, "node-old.example.com")
        self.assertEqual(stored.get_api_password(), "P1")

    def test_a_stale_password_write_after_a_rename_is_bound_to_the_stored_hostname(self) -> None:
        server = _server()
        stale, other = _fresh(server), _fresh(server)
        other.hostname = "node-new.example.com"
        other.save()
        stale.set_api_password("P3")
        stale.save(update_fields=["encrypted_api_password"])
        stored = _fresh(server)
        self.assertEqual(stored.hostname, "node-new.example.com")
        self.assertEqual(stored.get_api_password(), "P3")

    def test_two_saves_from_one_instance_after_another_writer_keep_the_newest_password(self) -> None:
        server = _fresh(_server())
        server.status = "maintenance"
        server.save()  # A successful save refreshes what this instance counts as loaded
        other = _fresh(server)
        other.set_api_password("P2")
        other.save()
        server.hostname = "node-new.example.com"
        server.save()
        self.assertEqual(_fresh(server).get_api_password(), "P2")

    def test_a_password_set_before_a_partial_save_is_still_written_by_the_password_save(self) -> None:
        server = _fresh(_server())
        server.set_api_password("P2")
        server.status = "maintenance"
        server.save(update_fields=["status"])
        server.save(update_fields=["encrypted_api_password"])
        self.assertEqual(_fresh(server).get_api_password(), "P2")

    def test_a_refresh_of_other_fields_keeps_a_pending_password(self) -> None:
        server = _fresh(_server())
        server.set_api_password("P2")
        server.refresh_from_db(fields=["status"])
        server.save(update_fields=["encrypted_api_password"])
        self.assertEqual(_fresh(server).get_api_password(), "P2")

    def test_a_refresh_given_a_generator_still_moves_the_baseline(self) -> None:
        server = _server()
        stale = _fresh(server)
        writer = _fresh(server)
        writer.set_api_password("B")
        writer.save()
        stale.refresh_from_db(fields=(name for name in ["encrypted_api_password"]))
        writer.set_api_password("C")
        writer.save()
        stale.save()  # Its password is what it read, not its own change: the newer one stays
        self.assertEqual(_fresh(server).get_api_password(), "C")

    def test_bulk_writes_of_the_hostname_are_refused(self) -> None:
        server = _server()
        with self.assertRaisesRegex(ValueError, "natural key"):
            VirtualminServer.objects.filter(pk=server.pk).update(hostname="other.example.com")
        server.hostname = "other.example.com"
        with self.assertRaisesRegex(ValueError, "natural key"):
            VirtualminServer.objects.bulk_update([server], ["hostname"])


class ServerHostnameTests(TestCase):
    def _server(self) -> Server:
        server = Server.objects.create(
            name="Host", hostname="host-old.example.com", server_type="shared", primary_ip="192.0.2.10",
            location="Bucharest", datacenter="DC1", cpu_model="x", cpu_cores=2, ram_gb=4, disk_type="ssd",
            disk_capacity_gb=50, os_type="linux",
        )
        server.set_api_password("S1")
        server.save()
        return server

    def test_a_hostname_changed_in_the_database_leaves_the_password_unreadable(self) -> None:
        server = self._server()
        Server._base_manager.filter(pk=server.pk).update(hostname="attacker.example.net")
        with self.assertRaises(DecryptionError):
            Server.objects.get(pk=server.pk).get_api_password()

    def test_an_orm_rename_keeps_the_password(self) -> None:
        server = self._server()
        server.hostname = "host-new.example.com"
        server.save()
        self.assertEqual(Server.objects.get(pk=server.pk).get_api_password(), "S1")


class AutocommitRenameTests(TransactionTestCase):
    """A caller outside any transaction (the edit view) renames on PostgreSQL: save() takes its own lock."""

    def test_a_rename_outside_a_transaction_keeps_the_password(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("select_for_update needs a transaction only on PostgreSQL")
        server = _server()
        server.hostname = "node-new.example.com"
        server.save()
        self.assertEqual(_fresh(server).get_api_password(), "P1")


class EditFormRenameTests(VirtualminViewsFixture):
    def _edit(self, **changes: str) -> Any:
        data = self.server_data()
        data.update(changes)
        return self.client.post(reverse("provisioning:virtualmin_server_edit", args=[self.server.pk]), data)

    def test_renaming_without_a_new_password_keeps_the_stored_one(self) -> None:
        self._edit(hostname="renamed-node.example.com", api_password="")
        self.server.refresh_from_db()
        self.assertEqual(self.server.hostname, "renamed-node.example.com")
        self.assertEqual(self.server.get_api_password(), "test_password")

    def test_renaming_with_a_new_password_stores_the_new_one(self) -> None:
        self._edit(hostname="renamed-node.example.com", api_password="Brand-New-Password-71!")
        self.server.refresh_from_db()
        self.assertEqual(self.server.get_api_password(), "Brand-New-Password-71!")

    def test_a_password_that_cannot_be_rebound_is_asked_for_again(self) -> None:
        other = _server("elsewhere.example.com", "other-secret")
        VirtualminServer._base_manager.filter(pk=self.server.pk).update(
            encrypted_api_password=bytes(VirtualminServer.objects.get(pk=other.pk).encrypted_api_password)
        )
        response = self._edit(hostname="renamed-node.example.com", api_password="")
        self.assertEqual(response.status_code, 200)
        self.assertIn("api_password", response.context["form"].errors)
        self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).hostname, "vm1.example.com")
