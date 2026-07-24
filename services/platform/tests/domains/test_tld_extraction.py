"""#237: TLD extraction must honour multi-label RO TLDs (.com.ro, .org.ro).

A bare ``rsplit('.', 1)`` truncated ``shop.com.ro`` to ``ro``, mislinking/mispricing
the Domain or falsely rejecting it. Extraction now matches the longest configured
``TLD.extension`` suffix; ``Domain.clean()`` shares that logic.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.domains.models import TLD, Domain
from apps.domains.services import DomainValidationService


class TldExtractionTestCase(TestCase):
    """extract_tld_from_domain resolves the longest configured TLD suffix."""

    def setUp(self) -> None:
        def _tld(extension: str) -> TLD:
            return TLD.objects.create(
                extension=extension,
                description=f".{extension}",
                registration_price_cents=1000,
                renewal_price_cents=1000,
                transfer_price_cents=1000,
                registrar_cost_cents=500,
                min_registration_period=1,
                max_registration_period=10,
            )

        self.tld_ro = _tld("ro")
        self.tld_com_ro = _tld("com.ro")
        self.tld_com = _tld("com")

    def test_multi_label_ro_tld_is_not_truncated(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("shop.com.ro"), "com.ro")

    def test_single_label_ro_still_resolves(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("example.ro"), "ro")

    def test_plain_com_resolves(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("example.com"), "com")

    def test_case_insensitive(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("SHOP.COM.RO"), "com.ro")

    def test_no_dot_returns_empty(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("localhost"), "")

    def test_unconfigured_tld_falls_back_to_last_label(self) -> None:
        # Nothing configured for .xyz — fall back to the last label so the caller's
        # own "unsupported TLD" handling fires instead of crashing.
        self.assertEqual(DomainValidationService.extract_tld_from_domain("example.xyz"), "xyz")

    def test_domain_clean_links_multi_label_tld(self) -> None:
        """Domain.clean() must resolve shop.com.ro to the .com.ro TLD, not .ro."""
        domain = Domain(name="shop.com.ro")
        domain.clean()
        self.assertEqual(domain.tld_id, self.tld_com_ro.id)

    def test_domain_clean_rejects_unsupported_tld(self) -> None:
        domain = Domain(name="example.xyz")
        with self.assertRaises(ValidationError):
            domain.clean()
