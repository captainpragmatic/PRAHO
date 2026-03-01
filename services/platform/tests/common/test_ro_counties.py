"""
Tests for Romanian city-to-county mapping (U1 TODO fix).

Verifies detect_county() resolves county seats and handles edge cases.
"""

from django.test import TestCase

from apps.common.ro_counties import CITY_TO_COUNTY, detect_county


class DetectCountyTests(TestCase):
    """U1: detect_county() resolves Romanian city seats to counties"""

    def test_county_seats_with_diacritics(self):
        """Known county seats with diacritics return correct county"""
        self.assertEqual(detect_county("Cluj-Napoca"), "Cluj")
        self.assertEqual(detect_county("Timișoara"), "Timiș")
        self.assertEqual(detect_county("Iași"), "Iași")
        self.assertEqual(detect_county("Brașov"), "Brașov")
        self.assertEqual(detect_county("Constanța"), "Constanța")

    def test_county_seats_without_diacritics(self):
        """ASCII variants of county seats also match"""
        self.assertEqual(detect_county("timisoara"), "Timiș")
        self.assertEqual(detect_county("iasi"), "Iași")
        self.assertEqual(detect_county("brasov"), "Brașov")
        self.assertEqual(detect_county("constanta"), "Constanța")

    def test_case_insensitive(self):
        """Lookup is case-insensitive"""
        self.assertEqual(detect_county("CLUJ-NAPOCA"), "Cluj")
        self.assertEqual(detect_county("bucurești"), "București")
        self.assertEqual(detect_county("TIMIȘOARA"), "Timiș")

    def test_anglicized_bucharest(self):
        """Common anglicized 'Bucharest' maps to București"""
        self.assertEqual(detect_county("Bucharest"), "București")
        self.assertEqual(detect_county("bucharest"), "București")

    def test_bucharest_sectors(self):
        """Bucharest sectors map to București"""
        for i in range(1, 7):
            self.assertEqual(detect_county(f"Sector {i}"), "București")

    def test_unknown_city_returns_empty(self):
        """Unknown cities return empty string"""
        self.assertEqual(detect_county("London"), "")
        self.assertEqual(detect_county("New York"), "")

    def test_empty_string_returns_empty(self):
        """Empty input returns empty string"""
        self.assertEqual(detect_county(""), "")

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped"""
        self.assertEqual(detect_county("  Cluj-Napoca  "), "Cluj")

    def test_all_41_counties_plus_bucharest_covered(self):
        """At least 42 entries (41 counties + Bucharest)"""
        self.assertGreaterEqual(len(CITY_TO_COUNTY), 42)

    def test_county_values_use_diacritics(self):
        """County values use proper Romanian diacritics"""
        self.assertEqual(detect_county("București"), "București")
        self.assertNotEqual(detect_county("București"), "Bucuresti")
