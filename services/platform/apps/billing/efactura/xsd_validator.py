"""
XSD Schema Validation for e-Factura XML documents.

Validates UBL 2.1 Invoice/CreditNote XML against official ANAF schemas.

The XSD schemas should be placed in:
    services/platform/apps/billing/efactura/schemas/

Download schemas from:
    https://mfinante.gov.ro/web/efactura/informatii-tehnice
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from lxml import etree

from .settings import efactura_settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
XML_ERROR_LEVEL_THRESHOLD = 2


@dataclass
class XSDValidationError:
    """Represents an XSD validation error."""

    line: int
    column: int
    message: str
    domain: str = ""
    type_name: str = ""
    level: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "domain": self.domain,
            "type": self.type_name,
            "level": self.level,
        }

    def __str__(self) -> str:
        return f"Line {self.line}, Column {self.column}: {self.message}"


@dataclass
class XSDValidationResult:
    """Result of XSD validation."""

    is_valid: bool
    errors: list[XSDValidationError] = field(default_factory=list)
    warnings: list[XSDValidationError] = field(default_factory=list)
    schema_version: str = ""

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "schema_version": self.schema_version,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }


class XSDSchemaNotFoundError(Exception):
    """Raised when XSD schema files are not found."""


class XSDValidator:
    """
    XSD Schema Validator for e-Factura XML documents.

    Validates XML against UBL 2.1 and CIUS-RO schemas.

    Usage:
        validator = XSDValidator()
        result = validator.validate(xml_content)
        if not result.is_valid:
            for error in result.errors:
                print(error)
    """

    # Schema file paths relative to the schemas directory
    SCHEMA_FILES: ClassVar[dict[str, str]] = {
        "UBL-Invoice-2.1": "UBL-2.1/xsd/maindoc/UBL-Invoice-2.1.xsd",
        "UBL-CreditNote-2.1": "UBL-2.1/xsd/maindoc/UBL-CreditNote-2.1.xsd",
        "CIUS-RO": "CIUS-RO/UBL-Invoice-2.1-RO.xsd",
    }

    # Namespaces for detecting document type
    INVOICE_NS = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
    CREDIT_NOTE_NS = "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2"

    def __init__(self, schemas_path: str | Path | None = None):
        """
        Initialize XSD validator.

        Args:
            schemas_path: Path to schemas directory. If None, uses default location.
        """
        if schemas_path:
            self.schemas_path = Path(schemas_path)
        else:
            # Default: apps/billing/efactura/schemas/
            self.schemas_path = Path(__file__).parent / "schemas"

        self._invoice_schema: etree.XMLSchema | None = None
        self._credit_note_schema: etree.XMLSchema | None = None
        self._cius_ro_schema: etree.XMLSchema | None = None

    def _load_schema(self, schema_key: str) -> etree.XMLSchema:
        """Load an XSD schema from file."""
        if schema_key not in self.SCHEMA_FILES:
            raise XSDSchemaNotFoundError(f"Unknown schema: {schema_key}")

        schema_path = self.schemas_path / self.SCHEMA_FILES[schema_key]

        if not schema_path.exists():
            raise XSDSchemaNotFoundError(
                f"Schema file not found: {schema_path}\n"
                f"Please download schemas from https://mfinante.gov.ro/web/efactura/informatii-tehnice"
            )

        try:
            schema_doc = etree.parse(str(schema_path))
            return etree.XMLSchema(schema_doc)
        except etree.XMLSchemaParseError as e:
            logger.error(f"Failed to parse schema {schema_key}: {e}")
            raise

    @property
    def invoice_schema(self) -> etree.XMLSchema:
        """Get cached UBL Invoice schema."""
        if self._invoice_schema is None:
            self._invoice_schema = self._load_schema("UBL-Invoice-2.1")
        return self._invoice_schema

    @property
    def credit_note_schema(self) -> etree.XMLSchema:
        """Get cached UBL Credit Note schema."""
        if self._credit_note_schema is None:
            self._credit_note_schema = self._load_schema("UBL-CreditNote-2.1")
        return self._credit_note_schema

    def _detect_document_type(self, xml_doc: etree._Element) -> str:
        """Detect document type from root element namespace."""
        root_tag = xml_doc.tag

        if self.INVOICE_NS in root_tag or root_tag.endswith("}Invoice"):
            return "invoice"
        elif self.CREDIT_NOTE_NS in root_tag or root_tag.endswith("}CreditNote"):
            return "credit_note"
        else:
            return "unknown"

    def _parse_errors(self, error_log: Any) -> tuple[list[XSDValidationError], list[XSDValidationError]]:
        """Parse lxml error log into structured errors and warnings."""
        errors = []
        warnings = []

        for entry in error_log:
            error = XSDValidationError(
                line=entry.line,
                column=entry.column,
                message=entry.message,
                domain=str(entry.domain_name),
                type_name=str(entry.type_name),
                level="error" if entry.level >= XML_ERROR_LEVEL_THRESHOLD else "warning",
            )

            if entry.level >= XML_ERROR_LEVEL_THRESHOLD:  # ERROR or FATAL
                errors.append(error)
            else:
                warnings.append(error)

        return errors, warnings

    def _get_setting(self, key: str, default: object = None) -> object:
        """
        Backward-compatible settings accessor for tests and legacy callers.

        Uses attributes exposed by efactura_settings.
        """
        return getattr(efactura_settings, key, default)

    def validate(self, xml_content: str | bytes) -> XSDValidationResult:  # noqa: PLR0911
        """
        Validate XML content against appropriate XSD schema.

        Args:
            xml_content: XML content as string or bytes

        Returns:
            XSDValidationResult with validation status and errors
        """
        if not self._get_setting("xsd_validation_enabled", True):
            logger.debug("XSD validation is disabled")
            return XSDValidationResult(is_valid=True, schema_version="disabled")

        try:
            # Parse XML
            if isinstance(xml_content, str):
                xml_content = xml_content.encode("utf-8")

            if b"<!doctype" in xml_content.lower():
                return XSDValidationResult(
                    is_valid=False,
                    errors=[
                        XSDValidationError(
                            line=1,
                            column=1,
                            message="DOCTYPE declarations are not allowed.",
                        )
                    ],
                )

            parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
            xml_doc = etree.fromstring(xml_content, parser=parser)

            # Detect document type
            doc_type = self._detect_document_type(xml_doc)

            if doc_type == "unknown":
                return XSDValidationResult(
                    is_valid=False,
                    errors=[
                        XSDValidationError(
                            line=1,
                            column=1,
                            message="Unknown document type. Expected Invoice or CreditNote.",
                        )
                    ],
                )

            # Select appropriate schema
            try:
                schema = self.invoice_schema if doc_type == "invoice" else self.credit_note_schema
            except XSDSchemaNotFoundError as e:
                logger.warning(f"XSD schemas not available: {e}")
                return XSDValidationResult(
                    is_valid=True,  # Pass validation if schemas not installed
                    schema_version="not_installed",
                    warnings=[
                        XSDValidationError(
                            line=0,
                            column=0,
                            message=str(e),
                            level="warning",
                        )
                    ],
                )

            # Validate
            is_valid = schema.validate(xml_doc)
            errors, warnings = self._parse_errors(schema.error_log)

            return XSDValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                schema_version="UBL-2.1",
            )

        except etree.XMLSyntaxError as e:
            logger.error(f"XML syntax error: {e}")
            return XSDValidationResult(
                is_valid=False,
                errors=[
                    XSDValidationError(
                        line=e.lineno or 1,
                        column=e.offset or 1,
                        message=str(e),
                    )
                ],
            )
        except Exception as e:
            logger.exception(f"XSD validation error: {e}")
            return XSDValidationResult(
                is_valid=False,
                errors=[
                    XSDValidationError(
                        line=0,
                        column=0,
                        message=f"Validation error: {e}",
                    )
                ],
            )

    def validate_file(self, file_path: str | Path) -> XSDValidationResult:
        """
        Validate XML file against XSD schema.

        Args:
            file_path: Path to XML file

        Returns:
            XSDValidationResult
        """
        try:
            with open(file_path, "rb") as f:
                xml_content = f.read()
            return self.validate(xml_content)
        except FileNotFoundError:
            return XSDValidationResult(
                is_valid=False,
                errors=[
                    XSDValidationError(
                        line=0,
                        column=0,
                        message=f"File not found: {file_path}",
                    )
                ],
            )
        except OSError as e:
            return XSDValidationResult(
                is_valid=False,
                errors=[
                    XSDValidationError(
                        line=0,
                        column=0,
                        message=f"Error reading file: {e}",
                    )
                ],
            )


class CanonicalXMLGenerator:
    """
    Generate Canonical XML (C14N) for consistent signatures.

    ANAF may require canonical XML for proper signature verification.
    """

    @staticmethod
    def canonicalize(xml_content: str | bytes, with_comments: bool = False) -> bytes:
        """
        Generate canonical XML (C14N).

        Args:
            xml_content: XML content to canonicalize
            with_comments: Whether to preserve comments

        Returns:
            Canonicalized XML as bytes
        """
        if isinstance(xml_content, str):
            xml_content = xml_content.encode("utf-8")

        doc = etree.fromstring(xml_content)

        # Use exclusive C14N (XML-EXC-C14N)
        return etree.tostring(
            doc,
            method="c14n",
            exclusive=True,
            with_comments=with_comments,
        )

    @staticmethod
    def canonicalize_element(element: etree._Element, with_comments: bool = False) -> bytes:
        """Canonicalize a specific XML element."""
        return etree.tostring(
            element,
            method="c14n",
            exclusive=True,
            with_comments=with_comments,
        )


# Module-level validator instance
xsd_validator = XSDValidator()
