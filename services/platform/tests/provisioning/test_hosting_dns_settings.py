"""The hosting-dns settings group (ADR-0061 P1.3).

The account zone holds every customer's account name, so it must never share a registrable domain
with the brand or the Portal: a customer site on a sibling name could set cookies for them. Its
zone and zone id are fixed while live names exist, and the feature cannot be switched on before
the zone, its id and its token are set. The token's access to the zone is proven where it is used,
by every sync, never by a network call inside the settings write.
"""

from __future__ import annotations

from django.test import TestCase, override_settings

from apps.provisioning import account_hostname_config as config
from apps.provisioning.account_hostname_models import AccountHostname
from apps.settings.services import SettingsService

ZONE = "praho-sites.net"
ZONE_ID = "0123456789abcdef0123456789abcdef"


def _write(key: str, value: object) -> str | None:
    """The refusal code of a write, or None when it is stored."""
    result = SettingsService.update_setting(key, value)
    return None if result.is_ok() else result.unwrap_err().code


@override_settings(PORTAL_DOMAIN="portal.pragmatichost.com", PLATFORM_DOMAIN="platform.pragmatichost.com")
class AccountZoneRegistrableDomainTests(TestCase):
    def test_a_zone_sharing_the_brand_or_portal_registrable_domain_is_refused(self) -> None:
        for zone in (
            "pragmatichost.com",  # equal to the registrable domain
            "sites.pragmatichost.com",  # a sibling of the Portal
            "x.portal.pragmatichost.com",  # a child of the Portal
            "PRAGMATICHOST.COM.",  # the same, written differently
        ):
            with self.subTest(zone=zone):
                self.assertEqual(_write("dns.account_hostname_zone", zone), "shares_brand_domain")

    def test_a_different_registrable_domain_is_accepted(self) -> None:
        self.assertIsNone(_write("dns.account_hostname_zone", ZONE))
        self.assertEqual(config.account_zone(), ZONE)

    def test_a_private_suffix_counts_as_its_own_registrable_domain(self) -> None:
        # github.io is a private suffix: two different users of it are different sites.
        with override_settings(PORTAL_DOMAIN="brand.github.io", PLATFORM_DOMAIN="brand.github.io"):
            self.assertIsNone(_write("dns.account_hostname_zone", "praho-sites.github.io"))
            self.assertEqual(_write("dns.account_hostname_zone", "x.brand.github.io"), "shares_brand_domain")


class AccountZoneLockTests(TestCase):
    def setUp(self) -> None:
        self.assertIsNone(_write("dns.account_hostname_zone", ZONE))
        self.assertIsNone(_write("dns.account_hostname_zone_id", ZONE_ID))

    def test_the_zone_and_its_id_cannot_change_while_names_are_live(self) -> None:
        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)
        self.assertEqual(_write("dns.account_hostname_zone", "other-sites.net"), "live_account_names")
        self.assertEqual(_write("dns.account_hostname_zone_id", "f" * 32), "live_account_names")
        self.assertIsNone(_write("dns.account_hostname_zone", ZONE), "re-saving the same zone is not a change")

    def test_retired_names_do_not_hold_the_zone(self) -> None:
        from django.utils import timezone  # noqa: PLC0415

        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE, retired_at=timezone.now())
        self.assertIsNone(_write("dns.account_hostname_zone", "other-sites.net"))

    def test_the_token_rotates_while_names_are_live(self) -> None:
        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)
        self.assertIsNone(_write("dns.account_zone_api_token", "new-token-value"))
        self.assertEqual(config.account_zone_api_token(), "new-token-value")

    def test_a_zone_beyond_dns_length_limits_is_refused(self) -> None:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        for zone in ("a" * 64 + ".example.net", ".".join(["a" * 60] * 5) + ".net"):
            with self.subTest(length=len(zone)):
                self.assertTrue(SettingsService.update_setting("dns.account_hostname_zone", zone).is_err())
        self.assertTrue(SettingsService.update_setting("dns.account_hostname_zone", "a" * 63 + ".example.net").is_ok())

    def test_the_longest_zone_accepted_fits_every_value_derived_from_it(self) -> None:
        from apps.provisioning.account_hostname_config import ZONE_MAX_LENGTH  # noqa: PLC0415
        from apps.provisioning.account_hostname_models import AccountNameCertificate  # noqa: PLC0415
        from apps.settings.services import SettingsService  # noqa: PLC0415

        zone = f"{'a' * 63}.{'b' * 63}.{'c' * (ZONE_MAX_LENGTH - 130)}.d"  # valid labels, exactly the maximum
        self.assertEqual(len(zone), ZONE_MAX_LENGTH)
        self.assertTrue(SettingsService.update_setting("dns.account_hostname_zone", zone).is_ok())
        self.assertTrue(SettingsService.update_setting("dns.account_hostname_zone", "e" + zone).is_err())
        fqdn = "x" * 8 + "." + zone
        key_ref = f"acme_certificate_key:{fqdn}@{'f' * 32}"
        self.assertLessEqual(len(fqdn), 253)
        self.assertLessEqual(len(key_ref), AccountNameCertificate._meta.get_field("current_key_ref").max_length)

    def test_a_zone_id_of_the_wrong_shape_is_refused(self) -> None:
        self.assertIsNotNone(_write("dns.account_hostname_zone_id", "not-a-zone-id"))


class EnableHostnamesTests(TestCase):
    def test_the_feature_cannot_be_switched_on_before_it_is_configured(self) -> None:
        self.assertEqual(_write("dns.account_hostnames_enabled", True), "hosting_dns_incomplete")
        self.assertFalse(config.account_hostnames_enabled())

    def test_the_feature_switches_on_once_zone_id_and_token_are_set(self) -> None:
        for key, value in (
            ("dns.account_hostname_zone", ZONE),
            ("dns.account_hostname_zone_id", ZONE_ID),
            ("dns.account_zone_api_token", "token-value"),
        ):
            self.assertIsNone(_write(key, value))
        self.assertIsNone(_write("dns.account_hostnames_enabled", True))
        self.assertTrue(config.account_hostnames_enabled())


class FlagOnByDefaultTests(TestCase):
    """The flag is on by default, but account names act only once the zone, its id and its token are set."""

    def _configure(self) -> None:
        for key, value in (
            ("dns.account_hostname_zone", ZONE),
            ("dns.account_hostname_zone_id", ZONE_ID),
            ("dns.account_zone_api_token", "token-value"),
        ):
            self.assertIsNone(_write(key, value))

    def test_on_by_default_once_configured_without_touching_the_flag(self) -> None:
        self._configure()

        self.assertTrue(config.account_hostnames_enabled())

    def test_nothing_happens_while_unconfigured_even_with_the_flag_on(self) -> None:
        self.assertFalse(config.account_hostnames_enabled())

    def test_the_flag_still_turns_it_off(self) -> None:
        self._configure()
        self.assertIsNone(_write("dns.account_hostnames_enabled", False))

        self.assertFalse(config.account_hostnames_enabled())

    def test_clearing_the_token_turns_it_off_again(self) -> None:
        self._configure()
        self.assertIsNone(_write("dns.account_zone_api_token", ""))

        self.assertFalse(config.account_hostnames_enabled())


class HostingDnsDefaultsTests(TestCase):
    def test_the_defaults_are_off_and_safe(self) -> None:
        self.assertFalse(config.account_hostnames_enabled())
        self.assertFalse(config.account_zone_psl_shipped())
        self.assertEqual(config.account_record_ttl_seconds(), 300)
        self.assertEqual(config.account_cert_weekly_budget(), 40)
        self.assertEqual(config.acme_directory_url(), "https://acme-v02.api.letsencrypt.org/directory")

    def test_the_record_ttl_takes_effect(self) -> None:
        self.assertIsNone(_write("dns.account_record_ttl_seconds", 600))
        self.assertEqual(config.account_record_ttl_seconds(), 600)

    def test_the_certificate_budget_takes_effect(self) -> None:
        self.assertIsNone(_write("dns.account_cert_weekly_budget", 25))
        self.assertEqual(config.account_cert_weekly_budget(), 25)

    def test_the_psl_switch_takes_effect(self) -> None:
        self.assertIsNone(_write("dns.account_zone_psl_shipped", True))
        self.assertTrue(config.account_zone_psl_shipped())

    def test_the_acme_directory_takes_effect(self) -> None:
        self.assertIsNone(_write("dns.account_acme_directory_url", "https://acme.example.test/dir"))
        self.assertEqual(config.acme_directory_url(), "https://acme.example.test/dir")

    def test_the_zone_id_takes_effect(self) -> None:
        self.assertIsNone(_write("dns.account_hostname_zone_id", ZONE_ID))
        self.assertEqual(config.account_zone_id(), ZONE_ID)


class PortalUrlBrandDomainTests(TestCase):
    def test_the_portal_url_setting_counts_as_a_brand_domain(self) -> None:
        self.assertIsNone(_write("portal.public_base_url", "https://clients.brand-hosting.ro"))
        self.assertEqual(_write("dns.account_hostname_zone", "sites.brand-hosting.ro"), "shares_brand_domain")
        self.assertIn("clients.brand-hosting.ro", config._brand_names())
