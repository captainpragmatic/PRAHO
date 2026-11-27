"""SQLite test runs refuse a value longer than its column, as PostgreSQL does.

SQLite ignores varchar lengths, and PR CI runs ordinary tests on SQLite, so a fixture writing six
characters into CloudProvider.code (varchar(3)) passed every PR gate and failed only at the
PostgreSQL nightly (#895). The test runners install a pre_save check on SQLite that raises the same
DataError PostgreSQL would. It does not see queryset.update() or bulk_create().
"""

from unittest import skipUnless

from django.db import DataError, connection
from django.db.models.signals import pre_save
from django.test import TestCase

from apps.infrastructure.models import CloudProvider


class SQLiteFieldLengthCheckTests(TestCase):
    def _provider(self, code: object) -> CloudProvider:
        return CloudProvider(name="Length Check Cloud", code=code, provider_type="hetzner", is_active=True)

    @skipUnless(connection.vendor == "sqlite", "the check's own message; PostgreSQL raises its own DataError")
    def test_a_value_longer_than_its_column_is_refused(self) -> None:
        with self.assertRaisesMessage(DataError, "CloudProvider.code"):
            self._provider("abcd").save()
        self.assertFalse(CloudProvider.objects.filter(name="Length Check Cloud").exists())

    def test_a_value_that_fits_is_saved(self) -> None:
        self._provider("abc").save()
        self.assertTrue(CloudProvider.objects.filter(code="abc").exists())

    @skipUnless(connection.vendor == "sqlite", "the check is installed only for SQLite")
    def test_a_value_that_becomes_too_long_once_converted_is_refused(self) -> None:
        """Django writes str(value) for a CharField, so 1234 is four characters, as PostgreSQL sees it."""
        with self.assertRaisesMessage(DataError, "CloudProvider.code"):
            self._provider(1234).save()

    @skipUnless(connection.vendor == "sqlite", "the check is installed only for SQLite")
    def test_a_partial_save_checks_only_the_fields_it_writes(self) -> None:
        """PostgreSQL accepts save(update_fields=...) when the unwritten field holds a too-long value."""
        provider = self._provider("abc")
        provider.save()
        provider.code = "abcd"
        provider.is_active = False
        provider.save(update_fields=["is_active"])
        self.assertFalse(CloudProvider.objects.get(pk=provider.pk).is_active)
        with self.assertRaisesMessage(DataError, "CloudProvider.code"):
            provider.save(update_fields=["code"])

    def test_a_deferred_field_is_not_read_to_check_it(self) -> None:
        """A save must not load a field the query deferred: the check would change what the save reads."""
        self._provider("abc").save()
        provider = CloudProvider.objects.defer("name").get(code="abc")
        self.assertIn("name", provider.get_deferred_fields())
        # Call the check itself: CloudProvider's own save signals may read the name for other reasons.
        from tests.field_lengths import _refuse_overlong_char_values  # noqa: PLC0415

        _refuse_overlong_char_values(CloudProvider, provider)
        self.assertIn("name", provider.get_deferred_fields(), "the check loaded the deferred field")

    def test_the_check_is_installed_exactly_when_the_database_is_sqlite(self) -> None:
        from tests.field_lengths import RECEIVER_UID  # noqa: PLC0415

        connected = any(entry[0][0] == RECEIVER_UID for entry in pre_save.receivers)
        self.assertEqual(connected, connection.vendor == "sqlite")
