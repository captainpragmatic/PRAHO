"""
Tests for file upload security validation service.

Tests cover:
- File extension validation
- MIME type validation
- Magic bytes validation
- Size limit enforcement
- Malicious content detection
- SVG sanitization
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from apps.common.file_upload_security import (
    ALLOWED_FILE_TYPES,
    FileCategory,
    FileUploadSecurityService,
    FileValidationResult,
    get_allowed_extensions,
    get_allowed_mime_types,
    validate_backup_upload,
    validate_document_upload,
    validate_image_upload,
)


class FileUploadSecurityServiceTests(TestCase):
    """Tests for FileUploadSecurityService."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.service = FileUploadSecurityService()

    def test_valid_jpeg_upload(self) -> None:
        """Test validation of a valid JPEG file."""
        # JPEG magic bytes
        jpeg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
        file = SimpleUploadedFile(
            "test.jpg",
            jpeg_content,
            content_type="image/jpeg",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.detected_extension, ".jpg")
        self.assertEqual(result.category, FileCategory.IMAGE)
        self.assertIsNotNone(result.file_hash)

    def test_valid_png_upload(self) -> None:
        """Test validation of a valid PNG file."""
        # PNG magic bytes
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"
        file = SimpleUploadedFile(
            "test.png",
            png_content,
            content_type="image/png",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.detected_extension, ".png")

    def test_valid_pdf_upload(self) -> None:
        """Test validation of a valid PDF file."""
        pdf_content = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        file = SimpleUploadedFile(
            "document.pdf",
            pdf_content,
            content_type="application/pdf",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.detected_extension, ".pdf")
        self.assertEqual(result.category, FileCategory.DOCUMENT)

    def test_invalid_extension_rejected(self) -> None:
        """Test that files with disallowed extensions are rejected."""
        file = SimpleUploadedFile(
            "malware.exe",
            b"MZ\x90\x00",  # PE header
            content_type="application/x-msdownload",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("not allowed", result.error_message or "")

    def test_php_file_rejected(self) -> None:
        """Test that PHP files are rejected."""
        file = SimpleUploadedFile(
            "shell.php",
            b"<?php system($_GET['cmd']); ?>",
            content_type="application/x-php",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_double_extension_rejected(self) -> None:
        """Test that double extensions don't bypass security."""
        # Malicious file disguised as image
        file = SimpleUploadedFile(
            "image.jpg.php",
            b"<?php evil(); ?>",
            content_type="application/x-php",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_file_size_limit_enforced(self) -> None:
        """Test that file size limits are enforced."""
        # Create a file larger than allowed (> 10MB for images)
        large_content = b"\xff\xd8\xff" + b"x" * (11 * 1024 * 1024)
        file = SimpleUploadedFile(
            "large.jpg",
            large_content,
            content_type="image/jpeg",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("exceeds maximum", result.error_message or "")

    def test_magic_bytes_mismatch_rejected(self) -> None:
        """Test that files with wrong magic bytes are rejected."""
        # File claims to be PNG but has different content
        file = SimpleUploadedFile(
            "fake.png",
            b"This is not a PNG file",
            content_type="image/png",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("content does not match", result.error_message or "")

    def test_malicious_script_in_file_detected(self) -> None:
        """Test that malicious scripts in files are detected."""
        # Image file with embedded script
        malicious_content = b"\xff\xd8\xff" + b"<script>alert('xss')</script>"
        file = SimpleUploadedFile(
            "malicious.jpg",
            malicious_content,
            content_type="image/jpeg",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("malicious", result.error_message.lower() if result.error_message else "")

    def test_svg_with_script_rejected(self) -> None:
        """Test that SVG files with scripts are rejected."""
        malicious_svg = b"""<?xml version="1.0"?>
        <svg xmlns="http://www.w3.org/2000/svg">
            <script>alert('xss')</script>
            <rect width="100" height="100"/>
        </svg>"""
        file = SimpleUploadedFile(
            "malicious.svg",
            malicious_svg,
            content_type="image/svg+xml",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_svg_with_onload_rejected(self) -> None:
        """Test that SVG files with event handlers are rejected."""
        malicious_svg = b"""<?xml version="1.0"?>
        <svg xmlns="http://www.w3.org/2000/svg" onload="alert('xss')">
            <rect width="100" height="100"/>
        </svg>"""
        file = SimpleUploadedFile(
            "malicious.svg",
            malicious_svg,
            content_type="image/svg+xml",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_php_content_in_image_rejected(self) -> None:
        """Test that PHP code in image files is detected."""
        malicious_content = b"\xff\xd8\xff" + b"<?php system('whoami'); ?>"
        file = SimpleUploadedFile(
            "photo.jpg",
            malicious_content,
            content_type="image/jpeg",
        )

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_zip_file_validation(self) -> None:
        """Test validation of ZIP archive files."""
        # ZIP magic bytes
        zip_content = b"PK\x03\x04" + b"\x00" * 26
        file = SimpleUploadedFile(
            "backup.zip",
            zip_content,
            content_type="application/zip",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.category, FileCategory.ARCHIVE)

    def test_gzip_file_validation(self) -> None:
        """Test validation of GZIP archive files."""
        # GZIP magic bytes
        gz_content = b"\x1f\x8b\x08\x00" + b"\x00" * 6
        file = SimpleUploadedFile(
            "backup.gz",
            gz_content,
            content_type="application/gzip",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)

    def test_json_file_validation(self) -> None:
        """Test validation of JSON data files."""
        json_content = b'{"key": "value", "number": 42}'
        file = SimpleUploadedFile(
            "data.json",
            json_content,
            content_type="application/json",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.category, FileCategory.DATA)

    def test_csv_file_validation(self) -> None:
        """Test validation of CSV data files."""
        csv_content = b"name,email,phone\nJohn,john@example.com,123456"
        file = SimpleUploadedFile(
            "data.csv",
            csv_content,
            content_type="text/csv",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)

    def test_file_hash_calculated(self) -> None:
        """Test that file hash is calculated correctly."""
        content = b"test content for hashing"
        file = SimpleUploadedFile(
            "test.txt",
            content,
            content_type="text/plain",
        )

        result = self.service.validate_file(file)

        self.assertTrue(result.is_valid)
        self.assertIsNotNone(result.file_hash)
        self.assertEqual(len(result.file_hash), 64)  # SHA-256 hex length

    def test_extension_filter_works(self) -> None:
        """Test that extension filtering works correctly."""
        service = FileUploadSecurityService(
            allowed_extensions={".jpg", ".png"},
        )

        # PDF should be rejected even though it's in ALLOWED_FILE_TYPES
        pdf_content = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        file = SimpleUploadedFile(
            "document.pdf",
            pdf_content,
            content_type="application/pdf",
        )

        result = service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("not allowed for this upload", result.error_message or "")

    def test_category_filter_works(self) -> None:
        """Test that category filtering works correctly."""
        service = FileUploadSecurityService(
            allowed_categories={FileCategory.IMAGE},
        )

        # PDF should be rejected
        pdf_content = b"%PDF-1.4\n"
        file = SimpleUploadedFile(
            "document.pdf",
            pdf_content,
            content_type="application/pdf",
        )

        result = service.validate_file(file)

        self.assertFalse(result.is_valid)

    def test_content_scanning_can_be_disabled(self) -> None:
        """Test that content scanning can be disabled."""
        service = FileUploadSecurityService(scan_content=False)

        # File with malicious content should pass without scanning
        # (Still fails magic bytes check though)
        malicious_content = b"\xff\xd8\xff" + b"<script>alert('xss')</script>"
        file = SimpleUploadedFile(
            "test.jpg",
            malicious_content,
            content_type="image/jpeg",
        )

        result = service.validate_file(file)

        # Should still pass since we disabled content scanning
        self.assertTrue(result.is_valid)

    def test_empty_filename_rejected(self) -> None:
        """Test that empty filename is rejected."""
        file = SimpleUploadedFile(
            "",
            b"content",
            content_type="text/plain",
        )
        file.name = ""

        result = self.service.validate_file(file)

        self.assertFalse(result.is_valid)
        self.assertIn("required", result.error_message or "")


class ConvenienceFunctionTests(TestCase):
    """Tests for convenience validation functions."""

    def test_validate_image_upload_accepts_images(self) -> None:
        """Test that validate_image_upload accepts valid images."""
        jpeg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
        file = SimpleUploadedFile(
            "photo.jpg",
            jpeg_content,
            content_type="image/jpeg",
        )

        result = validate_image_upload(file)

        self.assertTrue(result.is_valid)

    def test_validate_image_upload_rejects_documents(self) -> None:
        """Test that validate_image_upload rejects documents."""
        pdf_content = b"%PDF-1.4\n"
        file = SimpleUploadedFile(
            "document.pdf",
            pdf_content,
            content_type="application/pdf",
        )

        result = validate_image_upload(file)

        self.assertFalse(result.is_valid)

    def test_validate_document_upload_accepts_documents(self) -> None:
        """Test that validate_document_upload accepts valid documents."""
        pdf_content = b"%PDF-1.4\n"
        file = SimpleUploadedFile(
            "document.pdf",
            pdf_content,
            content_type="application/pdf",
        )

        result = validate_document_upload(file)

        self.assertTrue(result.is_valid)

    def test_validate_backup_upload_accepts_archives(self) -> None:
        """Test that validate_backup_upload accepts archives."""
        zip_content = b"PK\x03\x04" + b"\x00" * 26
        file = SimpleUploadedFile(
            "backup.zip",
            zip_content,
            content_type="application/zip",
        )

        result = validate_backup_upload(file)

        self.assertTrue(result.is_valid)

    def test_get_allowed_extensions(self) -> None:
        """Test that get_allowed_extensions returns expected list."""
        extensions = get_allowed_extensions()

        self.assertIn(".jpg", extensions)
        self.assertIn(".png", extensions)
        self.assertIn(".pdf", extensions)
        self.assertIn(".zip", extensions)
        self.assertNotIn(".exe", extensions)
        self.assertNotIn(".php", extensions)

    def test_get_allowed_mime_types(self) -> None:
        """Test that get_allowed_mime_types returns expected list."""
        mime_types = get_allowed_mime_types()

        self.assertIn("image/jpeg", mime_types)
        self.assertIn("image/png", mime_types)
        self.assertIn("application/pdf", mime_types)
        self.assertIn("application/zip", mime_types)


class AllowedFileTypesConfigTests(TestCase):
    """Tests for ALLOWED_FILE_TYPES configuration."""

    def test_all_extensions_have_mime_types(self) -> None:
        """Test that all file types have at least one MIME type."""
        for ext, file_type in ALLOWED_FILE_TYPES.items():
            self.assertTrue(
                len(file_type.mime_types) > 0,
                f"Extension {ext} has no MIME types defined",
            )

    def test_all_extensions_have_categories(self) -> None:
        """Test that all file types have a category."""
        for ext, file_type in ALLOWED_FILE_TYPES.items():
            self.assertIsInstance(
                file_type.category,
                FileCategory,
                f"Extension {ext} has invalid category",
            )

    def test_all_extensions_have_size_limits(self) -> None:
        """Test that all file types have reasonable size limits."""
        for ext, file_type in ALLOWED_FILE_TYPES.items():
            self.assertGreater(
                file_type.max_size_mb,
                0,
                f"Extension {ext} has invalid size limit",
            )
            self.assertLessEqual(
                file_type.max_size_mb,
                500,  # Max 500MB
                f"Extension {ext} has unreasonably large size limit",
            )

    def test_image_extensions_have_magic_bytes(self) -> None:
        """Test that binary image formats have magic bytes defined."""
        binary_image_extensions = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
        for ext in binary_image_extensions:
            if ext in ALLOWED_FILE_TYPES:
                file_type = ALLOWED_FILE_TYPES[ext]
                self.assertIsNotNone(
                    file_type.magic_bytes,
                    f"Binary image extension {ext} should have magic bytes",
                )
