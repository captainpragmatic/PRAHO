# =====================================
# 🧪 VIRTUALMIN RESPONSE PARSER TESTS
# ===============================================================================
"""
Tests for VirtualminResponseParser covering all code paths:
- JSON parsing (success, failure, malformed)
- XML parsing (success, error)
- Text parsing (success patterns, error patterns, list commands)
- Empty response handling
- Integration with fixture factories

Uses fixture factories from tests.fixtures.virtualmin.responses to ensure
the fixtures themselves produce parseable responses.
"""

import json

from django.test import SimpleTestCase

from apps.provisioning.virtualmin_gateway import VirtualminResponseParser
from tests.fixtures.virtualmin.responses import (
    create_domain,
    delete_domain,
    disable_domain,
    enable_domain,
    errors,
    info,
    list_bandwidth,
    list_domains,
)


# ---------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------


class ParserJSONSuccessTest(SimpleTestCase):
    """Test JSON responses with status=success."""

    def test_create_domain_success(self):
        fixture = create_domain.success(domain="new.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "create-domain")
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["command"], "create-domain")
        self.assertEqual(result["data"]["status"], "success")

    def test_delete_domain_success(self):
        fixture = delete_domain.success(domain="old.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "delete-domain")
        self.assertTrue(result["success"])

    def test_disable_domain_success(self):
        fixture = disable_domain.success(domain="suspended.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "disable-domain")
        self.assertTrue(result["success"])

    def test_enable_domain_success(self):
        fixture = enable_domain.success(domain="restored.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "enable-domain")
        self.assertTrue(result["success"])

    def test_list_domains_multiline(self):
        fixture = list_domains.multiline_response()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "list-domains")
        self.assertTrue(result["success"])
        self.assertIn("data", result["data"])

    def test_list_domains_name_only(self):
        fixture = list_domains.name_only(["a.com", "b.org"])
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "list-domains")
        self.assertTrue(result["success"])

    def test_list_domains_empty(self):
        fixture = list_domains.empty()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "list-domains")
        self.assertTrue(result["success"])

    def test_list_bandwidth_success(self):
        fixture = list_bandwidth.success(domain="bw.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "list-bandwidth")
        self.assertTrue(result["success"])

    def test_server_info(self):
        fixture = info.server_info(hostname="srv1.example.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "info")
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["data"]["hostname"], "srv1.example.com")


class ParserJSONFailureTest(SimpleTestCase):
    """Test JSON responses with status=failure or error key."""

    def test_create_domain_conflict(self):
        fixture = create_domain.conflict(domain="taken.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "create-domain")
        self.assertFalse(result["success"])
        self.assertIn("already exists", result["error"])

    def test_create_domain_quota_exceeded(self):
        fixture = create_domain.quota_exceeded()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "create-domain")
        self.assertFalse(result["success"])
        self.assertIn("quota", result["error"].lower())

    def test_delete_domain_not_found(self):
        fixture = delete_domain.not_found(domain="ghost.com")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "delete-domain")
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])

    def test_disable_not_found(self):
        fixture = disable_domain.not_found()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "disable-domain")
        self.assertFalse(result["success"])

    def test_enable_not_found(self):
        fixture = enable_domain.not_found()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "enable-domain")
        self.assertFalse(result["success"])

    def test_auth_failure(self):
        fixture = errors.auth_failure()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "list-domains")
        self.assertFalse(result["success"])
        self.assertIn("Login failed", result["error"])

    def test_generic_error(self):
        fixture = errors.generic(error_message="Something broke")
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "modify-domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Something broke")

    def test_rate_limited(self):
        fixture = errors.rate_limited()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "create-domain")
        self.assertFalse(result["success"])

    def test_server_offline(self):
        fixture = errors.server_offline()
        result = VirtualminResponseParser.parse_response(json.dumps(fixture), "info")
        self.assertFalse(result["success"])


class ParserJSONEdgeCasesTest(SimpleTestCase):
    """Test JSON edge cases: malformed, missing fields, unusual structures."""

    def test_malformed_json_falls_through_to_text(self):
        """Malformed JSON starting with { should fall through to text parser."""
        result = VirtualminResponseParser.parse_response("{not valid json", "info")
        # Falls through to text parser - no success/error patterns
        self.assertFalse(result["success"])

    def test_success_true_instead_of_status(self):
        """Some responses use 'success: true' instead of 'status: success'."""
        raw = json.dumps({"success": True, "data": {"count": 5}})
        result = VirtualminResponseParser.parse_response(raw, "list-domains")
        self.assertTrue(result["success"])

    def test_no_status_no_error_is_success(self):
        """Response without 'error' key and without 'status' is treated as success."""
        raw = json.dumps({"data": {"hostname": "test.com"}})
        result = VirtualminResponseParser.parse_response(raw, "info")
        self.assertTrue(result["success"])

    def test_error_key_present_means_failure(self):
        """Response with 'error' key is treated as failure."""
        raw = json.dumps({"error": "bad stuff happened", "data": {}})
        result = VirtualminResponseParser.parse_response(raw, "create-domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "bad stuff happened")

    def test_status_failure_with_error(self):
        raw = json.dumps({"status": "failure", "error": "Domain missing"})
        result = VirtualminResponseParser.parse_response(raw, "get-domain")
        self.assertFalse(result["success"])


# ---------------------------------------------------------------
# Empty response
# ---------------------------------------------------------------


class ParserEmptyResponseTest(SimpleTestCase):
    """Test empty/blank response handling."""

    def test_empty_string(self):
        result = VirtualminResponseParser.parse_response("", "info")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Empty response")

    def test_none_like_empty(self):
        """Whitespace-only is not empty but has no valid format."""
        result = VirtualminResponseParser.parse_response("   ", "info")
        # Not empty, not JSON/XML, falls to text parser
        self.assertFalse(result["success"])


# ---------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------


class ParserXMLTest(SimpleTestCase):
    """Test XML response parsing."""

    def test_xml_success(self):
        xml = "<response><status>ok</status><data>some data</data></response>"
        result = VirtualminResponseParser.parse_response(xml, "info")
        self.assertTrue(result["success"])
        self.assertIn("xml_response", result["data"])

    def test_xml_with_error_keyword(self):
        xml = "<response><error>Something failed</error></response>"
        result = VirtualminResponseParser.parse_response(xml, "create-domain")
        self.assertFalse(result["success"])

    def test_xml_with_failed_keyword(self):
        xml = "<response><status>Failed to create domain</status></response>"
        result = VirtualminResponseParser.parse_response(xml, "create-domain")
        self.assertFalse(result["success"])


# ---------------------------------------------------------------
# Text parsing
# ---------------------------------------------------------------


class ParserTextSuccessTest(SimpleTestCase):
    """Test text responses with success patterns."""

    def test_domain_created_successfully(self):
        text = "Creating virtual server test.com ..\nDomain test.com created successfully"
        result = VirtualminResponseParser.parse_response(text, "create-domain")
        self.assertTrue(result["success"])

    def test_domain_deleted_successfully(self):
        text = "Domain test.com deleted successfully"
        result = VirtualminResponseParser.parse_response(text, "delete-domain")
        self.assertTrue(result["success"])

    def test_completed_pattern(self):
        text = "Backup completed for test.com"
        result = VirtualminResponseParser.parse_response(text, "backup-domain")
        self.assertTrue(result["success"])

    def test_modified_pattern(self):
        text = "Virtual server test.com modified"
        result = VirtualminResponseParser.parse_response(text, "modify-domain")
        self.assertTrue(result["success"])


class ParserTextErrorTest(SimpleTestCase):
    """Test text responses with error patterns."""

    def test_error_colon_pattern(self):
        text = "Error: Cannot connect to server"
        result = VirtualminResponseParser.parse_response(text, "info")
        self.assertFalse(result["success"])
        self.assertIn("Error:", result["error"])

    def test_failed_colon_pattern(self):
        text = "Failed: DNS zone creation failed"
        result = VirtualminResponseParser.parse_response(text, "create-domain")
        self.assertFalse(result["success"])

    def test_not_found_pattern(self):
        text = "Virtual server ghost.com not found"
        result = VirtualminResponseParser.parse_response(text, "get-domain")
        self.assertFalse(result["success"])

    def test_permission_denied_pattern(self):
        text = "Permission denied for user admin"
        result = VirtualminResponseParser.parse_response(text, "delete-domain")
        self.assertFalse(result["success"])

    def test_unauthorized_pattern(self):
        text = "Unauthorized access attempt"
        result = VirtualminResponseParser.parse_response(text, "list-domains")
        self.assertFalse(result["success"])

    def test_forbidden_pattern(self):
        text = "Action forbidden by server policy"
        result = VirtualminResponseParser.parse_response(text, "modify-domain")
        self.assertFalse(result["success"])

    def test_invalid_pattern(self):
        text = "Invalid domain name specified"
        result = VirtualminResponseParser.parse_response(text, "create-domain")
        self.assertFalse(result["success"])


class ParserTextListCommandTest(SimpleTestCase):
    """Test text responses for list-* commands (special handling)."""

    def test_list_command_always_succeeds(self):
        """list-* programs return success even without success keywords."""
        text = "domain1.com\ndomain2.com\ndomain3.com"
        result = VirtualminResponseParser.parse_response(text, "list-domains")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["data"]["items"]), 3)

    def test_list_command_empty_data(self):
        """List command with no matching data still succeeds."""
        text = "No matching domains"
        result = VirtualminResponseParser.parse_response(text, "list-domains")
        # list-* special handling returns success
        self.assertTrue(result["success"])

    def test_list_command_error_pattern_takes_precedence(self):
        """Error patterns take precedence over list-* special handling."""
        text = "Domain not found on this server"
        # "not found" error pattern matches before list-* special handling
        result = VirtualminResponseParser.parse_response(text, "list-domains")
        self.assertFalse(result["success"])

    def test_list_bandwidth_text(self):
        text = "domain1.com,1024,2048\ndomain2.com,512,1024"
        result = VirtualminResponseParser.parse_response(text, "list-bandwidth")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["data"]["items"]), 2)


class ParserTextAmbiguousTest(SimpleTestCase):
    """Test text responses with no clear success or error patterns."""

    def test_unknown_format(self):
        text = "Some random output with no patterns"
        result = VirtualminResponseParser.parse_response(text, "info")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Unknown response format")


# ---------------------------------------------------------------
# Fixture integration: verify all fixture factories produce parseable JSON
# ---------------------------------------------------------------


class ParserFixtureIntegrationTest(SimpleTestCase):
    """Verify every fixture factory produces valid JSON that the parser handles."""

    def _parse_fixture(self, fixture: dict, program: str) -> dict:
        return VirtualminResponseParser.parse_response(json.dumps(fixture), program)

    def test_all_create_domain_fixtures(self):
        self.assertTrue(self._parse_fixture(create_domain.success(), "create-domain")["success"])
        self.assertFalse(self._parse_fixture(create_domain.conflict(), "create-domain")["success"])
        self.assertFalse(self._parse_fixture(create_domain.quota_exceeded(), "create-domain")["success"])
        self.assertFalse(self._parse_fixture(create_domain.invalid_domain(), "create-domain")["success"])

    def test_all_delete_domain_fixtures(self):
        self.assertTrue(self._parse_fixture(delete_domain.success(), "delete-domain")["success"])
        self.assertFalse(self._parse_fixture(delete_domain.not_found(), "delete-domain")["success"])

    def test_all_disable_domain_fixtures(self):
        self.assertTrue(self._parse_fixture(disable_domain.success(), "disable-domain")["success"])
        self.assertFalse(self._parse_fixture(disable_domain.not_found(), "disable-domain")["success"])
        self.assertFalse(self._parse_fixture(disable_domain.already_disabled(), "disable-domain")["success"])

    def test_all_enable_domain_fixtures(self):
        self.assertTrue(self._parse_fixture(enable_domain.success(), "enable-domain")["success"])
        self.assertFalse(self._parse_fixture(enable_domain.not_found(), "enable-domain")["success"])
        self.assertFalse(self._parse_fixture(enable_domain.already_enabled(), "enable-domain")["success"])

    def test_all_list_domains_fixtures(self):
        self.assertTrue(self._parse_fixture(list_domains.multiline_response(), "list-domains")["success"])
        self.assertTrue(self._parse_fixture(list_domains.name_only(), "list-domains")["success"])
        self.assertTrue(self._parse_fixture(list_domains.empty(), "list-domains")["success"])
        self.assertTrue(self._parse_fixture(list_domains.single_domain(), "list-domains")["success"])

    def test_all_list_bandwidth_fixtures(self):
        self.assertTrue(self._parse_fixture(list_bandwidth.success(), "list-bandwidth")["success"])
        self.assertTrue(self._parse_fixture(list_bandwidth.empty(), "list-bandwidth")["success"])

    def test_all_info_fixtures(self):
        self.assertTrue(self._parse_fixture(info.server_info(), "info")["success"])

    def test_all_error_fixtures(self):
        self.assertFalse(self._parse_fixture(errors.auth_failure(), "list-domains")["success"])
        self.assertFalse(self._parse_fixture(errors.not_found(), "get-domain")["success"])
        self.assertFalse(self._parse_fixture(errors.generic(), "modify-domain")["success"])
        self.assertFalse(self._parse_fixture(errors.rate_limited(), "create-domain")["success"])
        self.assertFalse(self._parse_fixture(errors.server_offline(), "info")["success"])

    def test_fixture_parameterization(self):
        """Verify fixtures work with custom parameters."""
        fixture = create_domain.success(domain="custom.ro", username="customuser")
        result = self._parse_fixture(fixture, "create-domain")
        self.assertTrue(result["success"])
        self.assertIn("custom.ro", result["data"]["output"])

        fixture = list_domains.single_domain(domain="my.ro", disk_usage="999 MB")
        result = self._parse_fixture(fixture, "list-domains")
        self.assertTrue(result["success"])
