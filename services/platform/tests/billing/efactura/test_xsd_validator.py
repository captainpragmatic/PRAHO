"""
Comprehensive tests for XSD validation and Canonical XML.

Tests cover:
- XSD validation against UBL schemas
- Error parsing and reporting
- Canonical XML generation
- Document type detection
- Edge cases and error handling
"""

from unittest.mock import MagicMock, Mock, patch

from django.test import TestCase, override_settings
from lxml import etree

from apps.billing.efactura.xsd_validator import (
    CanonicalXMLGenerator,
    XSDSchemaNotFoundError,
    XSDValidationError,
    XSDValidationResult,
    XSDValidator,
)


class XSDValidationErrorTestCase(TestCase):
    """Test XSDValidationError dataclass."""

    def test_error_creation(self):
        """Test creating validation error."""
        error = XSDValidationError(
            line=10,
            column=5,
            message="Missing required element",
            domain="SCHEMASV",
            type_name="ELEMENT_CONTENT",
            level="error",
        )
        self.assertEqual(error.line, 10)
        self.assertEqual(error.column, 5)
        self.assertIn("Missing", error.message)

    def test_error_to_dict(self):
        """Test error serialization to dict."""
        error = XSDValidationError(
            line=10,
            column=5,
            message="Test error",
        )
        result = error.to_dict()
        self.assertIn("line", result)
        self.assertIn("message", result)
        self.assertEqual(result["line"], 10)

    def test_error_str_representation(self):
        """Test string representation of error."""
        error = XSDValidationError(line=10, column=5, message="Test error")
        self.assertIn("10", str(error))
        self.assertIn("5", str(error))
        self.assertIn("Test error", str(error))


class XSDValidationResultTestCase(TestCase):
    """Test XSDValidationResult dataclass."""

    def test_valid_result(self):
        """Test valid result."""
        result = XSDValidationResult(is_valid=True)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.error_count, 0)
        self.assertEqual(result.warning_count, 0)

    def test_invalid_result_with_errors(self):
        """Test invalid result with errors."""
        errors = [
            XSDValidationError(line=1, column=1, message="Error 1"),
            XSDValidationError(line=2, column=1, message="Error 2"),
        ]
        result = XSDValidationResult(is_valid=False, errors=errors)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_count, 2)

    def test_result_with_warnings(self):
        """Test result with warnings."""
        warnings = [
            XSDValidationError(line=1, column=1, message="Warning", level="warning"),
        ]
        result = XSDValidationResult(is_valid=True, warnings=warnings)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 1)

    def test_to_dict_serialization(self):
        """Test serialization to dict."""
        result = XSDValidationResult(
            is_valid=True,
            schema_version="UBL-2.1",
        )
        data = result.to_dict()
        self.assertIn("is_valid", data)
        self.assertIn("schema_version", data)
        self.assertEqual(data["schema_version"], "UBL-2.1")


class XSDValidatorTestCase(TestCase):
    """Test XSDValidator class."""

    def setUp(self):
        self.validator = XSDValidator()

    def test_validator_initialization(self):
        """Test validator initializes correctly."""
        self.assertIsNotNone(self.validator.schemas_path)

    def test_detect_invoice_document_type(self):
        """Test detecting Invoice document type."""
        xml = """<?xml version="1.0"?>
        <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
        </Invoice>"""
        doc = etree.fromstring(xml.encode())
        doc_type = self.validator._detect_document_type(doc)
        self.assertEqual(doc_type, "invoice")

    def test_detect_credit_note_document_type(self):
        """Test detecting CreditNote document type."""
        xml = """<?xml version="1.0"?>
        <CreditNote xmlns="urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2">
        </CreditNote>"""
        doc = etree.fromstring(xml.encode())
        doc_type = self.validator._detect_document_type(doc)
        self.assertEqual(doc_type, "credit_note")

    def test_detect_unknown_document_type(self):
        """Test detecting unknown document type."""
        xml = """<?xml version="1.0"?>
        <Unknown xmlns="urn:example:unknown">
        </Unknown>"""
        doc = etree.fromstring(xml.encode())
        doc_type = self.validator._detect_document_type(doc)
        self.assertEqual(doc_type, "unknown")

    def test_validate_invalid_xml_syntax(self):
        """Test validation with invalid XML syntax."""
        xml = "This is not XML at all"
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.errors), 0)

    def test_validate_malformed_xml(self):
        """Test validation with malformed XML."""
        xml = "<Invoice><unclosed>"
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)

    def test_validate_unknown_document_type(self):
        """Test validation with unknown document type."""
        xml = """<?xml version="1.0"?>
        <Unknown xmlns="urn:example:unknown">
        </Unknown>"""
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Unknown document" in e.message for e in result.errors))

    @override_settings(EFACTURA_VALIDATION_XSD_ENABLED=False)
    @patch.object(XSDValidator, "_get_setting", return_value=False)
    def test_validation_disabled(self, mock_setting):
        """Test validation when disabled."""
        # We need to mock the settings check
        with patch("apps.billing.efactura.xsd_validator.efactura_settings") as mock_settings:
            mock_settings.xsd_validation_enabled = False
            validator = XSDValidator()
            result = validator.validate("<Invoice/>")
            self.assertTrue(result.is_valid)
            self.assertEqual(result.schema_version, "disabled")

    def test_validate_accepts_bytes(self):
        """Test validation accepts bytes input."""
        xml = b"""<?xml version="1.0"?>
        <Unknown xmlns="urn:example:unknown">
        </Unknown>"""
        result = self.validator.validate(xml)
        # Should parse but fail on unknown type
        self.assertFalse(result.is_valid)

    def test_validate_accepts_string(self):
        """Test validation accepts string input."""
        xml = """<?xml version="1.0"?>
        <Unknown xmlns="urn:example:unknown">
        </Unknown>"""
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)


class XSDValidatorSchemaLoadingTestCase(TestCase):
    """Test schema loading functionality."""

    def test_schema_not_found_error(self):
        """Test XSDSchemaNotFoundError is raised for missing schemas."""
        validator = XSDValidator(schemas_path="/nonexistent/path")
        with self.assertRaises(XSDSchemaNotFoundError):
            _ = validator.invoice_schema

    def test_unknown_schema_key(self):
        """Test loading unknown schema key."""
        validator = XSDValidator()
        with self.assertRaises(XSDSchemaNotFoundError):
            validator._load_schema("nonexistent_schema")

    def test_schema_caching(self):
        """Test schemas are cached after loading."""
        validator = XSDValidator()
        # Try to load - will fail if no schemas installed
        try:
            schema1 = validator.invoice_schema
            schema2 = validator.invoice_schema
            self.assertIs(schema1, schema2)
        except XSDSchemaNotFoundError:
            # Expected if schemas not installed
            pass


class XSDValidatorFileValidationTestCase(TestCase):
    """Test file validation functionality."""

    def test_validate_nonexistent_file(self):
        """Test validating non-existent file."""
        validator = XSDValidator()
        result = validator.validate_file("/nonexistent/file.xml")
        self.assertFalse(result.is_valid)
        self.assertTrue(any("not found" in e.message for e in result.errors))


class CanonicalXMLGeneratorTestCase(TestCase):
    """Test CanonicalXMLGenerator class."""

    def test_canonicalize_simple_xml(self):
        """Test canonicalizing simple XML."""
        xml = """<?xml version="1.0"?>
        <root>
            <child>text</child>
        </root>"""
        result = CanonicalXMLGenerator.canonicalize(xml)
        self.assertIsInstance(result, bytes)
        # C14N removes XML declaration and normalizes whitespace
        self.assertNotIn(b"<?xml", result)

    def test_canonicalize_preserves_content(self):
        """Test canonicalization preserves content."""
        xml = "<root><child>test value</child></root>"
        result = CanonicalXMLGenerator.canonicalize(xml)
        self.assertIn(b"test value", result)

    def test_canonicalize_normalizes_attributes(self):
        """Test canonicalization normalizes attribute order."""
        xml = '<root b="2" a="1"/>'
        result = CanonicalXMLGenerator.canonicalize(xml)
        # In C14N, attributes are sorted alphabetically
        decoded = result.decode("utf-8")
        a_pos = decoded.find('a="1"')
        b_pos = decoded.find('b="2"')
        self.assertLess(a_pos, b_pos)

    def test_canonicalize_removes_comments_by_default(self):
        """Test canonicalization removes comments by default."""
        xml = "<root><!-- comment --><child/></root>"
        result = CanonicalXMLGenerator.canonicalize(xml, with_comments=False)
        self.assertNotIn(b"comment", result)

    def test_canonicalize_preserves_comments_when_requested(self):
        """Test canonicalization preserves comments when requested."""
        xml = "<root><!-- comment --><child/></root>"
        result = CanonicalXMLGenerator.canonicalize(xml, with_comments=True)
        self.assertIn(b"comment", result)

    def test_canonicalize_element(self):
        """Test canonicalizing a specific element."""
        xml = "<root><child>test</child></root>"
        doc = etree.fromstring(xml.encode())
        child = doc.find("child")
        result = CanonicalXMLGenerator.canonicalize_element(child)
        self.assertIn(b"<child>test</child>", result)

    def test_canonicalize_accepts_bytes(self):
        """Test canonicalization accepts bytes input."""
        xml = b"<root><child/></root>"
        result = CanonicalXMLGenerator.canonicalize(xml)
        self.assertIsInstance(result, bytes)

    def test_canonicalize_handles_namespaces(self):
        """Test canonicalization handles namespaces correctly."""
        xml = """<root xmlns="urn:example" xmlns:ns="urn:other">
            <ns:child/>
        </root>"""
        result = CanonicalXMLGenerator.canonicalize(xml)
        self.assertIn(b"xmlns", result)


class XSDValidatorEdgeCasesTestCase(TestCase):
    """Test edge cases and error conditions."""

    def test_empty_xml(self):
        """Test validation with empty string."""
        validator = XSDValidator()
        result = validator.validate("")
        self.assertFalse(result.is_valid)

    def test_whitespace_only_xml(self):
        """Test validation with whitespace only."""
        validator = XSDValidator()
        result = validator.validate("   \n\t  ")
        self.assertFalse(result.is_valid)

    def test_xml_with_encoding_declaration(self):
        """Test XML with encoding declaration."""
        xml = '<?xml version="1.0" encoding="UTF-8"?><Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>'
        validator = XSDValidator()
        result = validator.validate(xml)
        # Should at least parse correctly
        self.assertIsNotNone(result)

    def test_xml_with_bom(self):
        """Test XML with BOM (Byte Order Mark)."""
        bom = b"\xef\xbb\xbf"
        xml = bom + b'<?xml version="1.0"?><Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>'
        validator = XSDValidator()
        # lxml should handle BOM
        result = validator.validate(xml)
        self.assertIsNotNone(result)

    def test_very_large_xml(self):
        """Test validation with large XML (performance test)."""
        # Create XML with many elements
        lines = ["<line>Content</line>" for _ in range(1000)]
        xml = f'<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">{"".join(lines)}</Invoice>'
        validator = XSDValidator()
        result = validator.validate(xml)
        self.assertIsNotNone(result)

    def test_xml_with_special_characters(self):
        """Test XML with special characters."""
        xml = '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><Note>Special: &amp; &lt; &gt; "quotes"</Note></Invoice>'
        validator = XSDValidator()
        result = validator.validate(xml)
        self.assertIsNotNone(result)

    def test_xml_with_unicode(self):
        """Test XML with Unicode characters."""
        xml = '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><Note>România: șțăîâ</Note></Invoice>'
        validator = XSDValidator()
        result = validator.validate(xml)
        self.assertIsNotNone(result)


class XSDValidatorErrorParsingTestCase(TestCase):
    """Test error log parsing."""

    def test_parse_multiple_errors(self):
        """Test parsing multiple validation errors."""
        validator = XSDValidator()

        # Create mock error log
        class MockError:
            def __init__(self, line, col, msg, level):
                self.line = line
                self.column = col
                self.message = msg
                self.level = level
                self.domain_name = "SCHEMASV"
                self.type_name = "ERROR"

        mock_log = [
            MockError(1, 1, "Error 1", 2),
            MockError(2, 5, "Error 2", 2),
            MockError(3, 10, "Warning", 1),
        ]

        errors, warnings = validator._parse_errors(mock_log)
        self.assertEqual(len(errors), 2)
        self.assertEqual(len(warnings), 1)
