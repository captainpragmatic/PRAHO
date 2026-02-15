"""
🔒 Ticket Security Module - File Upload and Validation Security

Comprehensive security framework for ticket file attachments:
- Magic number validation for file type verification
- Content pattern analysis for malicious script detection
- Secure file size limits and storage paths
- Extensible framework for future virus scanning integration
"""

import logging
import mimetypes
import secrets
from pathlib import Path

# Optional dependency for enhanced MIME type detection
try:
    import magic  # type: ignore[import-not-found]

    HAS_PYTHON_MAGIC = True
except ImportError:
    magic = None
    HAS_PYTHON_MAGIC = False

from typing import TypedDict

from django.core.files.uploadedfile import UploadedFile
from django.utils import timezone

from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)

# Security constants - configurable via SettingsService
_DEFAULT_MAX_FILE_SIZE_BYTES = 10485760  # 10MB limit
MAX_FILENAME_LENGTH = 255  # Structural - filesystem limit
_DEFAULT_ALLOWED_EXTENSIONS = [".pdf", ".txt", ".png", ".jpg", ".jpeg", ".doc", ".docx"]

# Magic number signatures for file type validation
MAGIC_NUMBER_SIGNATURES = {
    "application/pdf": [b"%PDF"],
    "image/jpeg": [b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "application/msword": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],  # .doc
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
        b"PK\x03\x04"  # .docx (ZIP-based)
    ],
    "text/plain": [],  # Text files can have various starts
}

# Suspicious content patterns to detect
SUSPICIOUS_PATTERNS = [
    b"<script",
    b"javascript:",
    b"vbscript:",
    b"data:text/html",
    b"<?php",
    b"<%",
    b"eval(",
    b"exec(",
    b"system(",
    b"<iframe",
    b"<object",
    b"<embed",
    b"<form",
    # Add more patterns as needed
]


class FileSecurityError(Exception):
    """Custom exception for file security violations"""


class ScanStats(TypedDict):
    files_scanned: int
    files_rejected: int
    rejection_reasons: dict[str, int]


class FileSecurityScanner:
    """
    🔒 Comprehensive file security scanner for ticket attachments

    Provides multiple layers of security validation:
    1. File extension validation
    2. MIME type verification
    3. Magic number validation
    4. Content pattern analysis
    5. File size limits
    6. Secure filename generation

    Future enhancement: ClamAV virus scanning integration
    """

    def __init__(self) -> None:
        self.scan_stats: ScanStats = {"files_scanned": 0, "files_rejected": 0, "rejection_reasons": {}}

    def scan_uploaded_file(self, uploaded_file: UploadedFile, original_filename: str | None = None) -> tuple[bool, str]:  # noqa: PLR0911
        """
        🔍 Comprehensive security scan of uploaded file

        Args:
            uploaded_file: Django UploadedFile instance
            original_filename: Original filename for logging

        Returns:
            Tuple[bool, str]: (is_safe, message)
        """
        self.scan_stats["files_scanned"] += 1
        filename = original_filename or uploaded_file.name or ""

        try:
            # Step 1: Basic filename validation
            if not self._validate_filename(filename):
                return self._reject_file("Invalid filename", filename)

            # Step 2: File extension validation
            if not self._validate_file_extension(filename):
                return self._reject_file("Dangerous file extension", filename)

            # Step 3: File size validation
            if not self._validate_file_size(uploaded_file):
                max_file_size = SettingsService.get_integer_setting(
                    "tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES
                )
                return self._reject_file(
                    f"File too large ({uploaded_file.size} bytes > {max_file_size})", filename
                )

            # Step 4: MIME type validation
            detected_mime = self._detect_mime_type(uploaded_file)
            if not self._validate_mime_type(detected_mime):
                return self._reject_file(f"Invalid MIME type: {detected_mime}", filename)

            # Step 5: Magic number validation
            if not self._validate_magic_numbers(uploaded_file, detected_mime):
                return self._reject_file("Magic number mismatch - file type spoofing detected", filename)

            # Step 6: Content pattern analysis
            if not self._validate_file_content(uploaded_file):
                return self._reject_file("Suspicious content patterns detected", filename)

            # TODO: Step 7: Optional: integrate ClamAV scanning behind a feature flag

            # File passed all security checks
            logger.info(f"✅ [Ticket Security] File security scan passed: {filename}")
            return True, "File security scan passed"

        except Exception as e:
            logger.error(f"🔥 [Ticket Security] File scan failed for {filename}: {e}")
            return self._reject_file("Security scan failed", filename)

    def _validate_filename(self, filename: str) -> bool:
        """Validate filename for security issues"""
        if not filename or len(filename) > MAX_FILENAME_LENGTH:
            return False

        # Check for path traversal attempts
        if ".." in filename or "/" in filename or "\\" in filename:
            logger.warning(f"🚨 [Ticket Security] Path traversal attempt in filename: {filename}")
            return False

        # Check for suspicious characters
        suspicious_chars = ["<", ">", ":", '"', "|", "?", "*", "\0"]
        if any(char in filename for char in suspicious_chars):
            logger.warning(f"🚨 [Ticket Security] Suspicious characters in filename: {filename}")
            return False

        return True

    def _validate_file_extension(self, filename: str) -> bool:
        """Validate file extension against allowlist"""
        file_ext = Path(filename).suffix.lower()
        allowed_extensions = set(
            SettingsService.get_list_setting(
                "tickets.allowed_file_extensions", _DEFAULT_ALLOWED_EXTENSIONS
            )
        )

        if file_ext not in allowed_extensions:
            logger.warning(f"🚨 [Ticket Security] Blocked file extension: {file_ext}")
            return False

        # Special check for double extensions (e.g., .txt.exe)
        name_parts = filename.lower().split(".")
        min_double_ext_parts = 3
        if len(name_parts) >= min_double_ext_parts:  # More than one extension
            for part in name_parts[1:-1]:  # Check middle extensions
                if f".{part}" in {".exe", ".bat", ".cmd", ".scr", ".pif", ".com"}:
                    logger.warning(f"🚨 [Ticket Security] Dangerous double extension: {filename}")
                    return False

        return True

    def _validate_file_size(self, uploaded_file: UploadedFile) -> bool:
        """Validate file size against security limits"""
        max_file_size = SettingsService.get_integer_setting(
            "tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES
        )
        size = uploaded_file.size or 0
        if size > max_file_size:
            logger.warning(f"🚨 [Ticket Security] File too large: {size} bytes")
            return False

        if size == 0:
            logger.warning("🚨 [Ticket Security] Empty file detected")
            return False

        return True

    def _detect_mime_type(self, uploaded_file: UploadedFile) -> str:  # noqa: PLR0911
        """Detect MIME type using magic numbers or fallback to mimetypes"""
        try:
            uploaded_file.seek(0)
            file_header = uploaded_file.read(1024)  # Read first 1KB
            uploaded_file.seek(0)

            if HAS_PYTHON_MAGIC and magic:
                # Use python-magic for accurate MIME detection
                detected_mime = magic.from_buffer(file_header, mime=True)
                return str(detected_mime)
            else:
                # Fallback to mimetypes module and basic magic number detection
                detected_mime, _ = mimetypes.guess_type(uploaded_file.name or "")
                if detected_mime:
                    return detected_mime

                # Basic magic number detection for common types
                if file_header.startswith(b"%PDF"):
                    return "application/pdf"
                elif file_header.startswith(b"\xff\xd8\xff"):
                    return "image/jpeg"
                elif file_header.startswith(b"\x89PNG\r\n\x1a\n"):
                    return "image/png"
                elif file_header.startswith(b"PK\x03\x04"):
                    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                elif file_header.startswith(b"\xd0\xcf\x11\xe0"):
                    return "application/msword"
                else:
                    return "application/octet-stream"

        except Exception as e:
            logger.error(f"🔥 [Ticket Security] MIME detection failed: {e}")
            return "application/octet-stream"  # Generic binary type

    def _validate_mime_type(self, mime_type: str) -> bool:
        """Validate MIME type against allowlist"""
        allowed_mimes = set(MAGIC_NUMBER_SIGNATURES.keys())

        if mime_type not in allowed_mimes:
            logger.warning(f"🚨 [Ticket Security] Blocked MIME type: {mime_type}")
            return False

        return True

    def _validate_magic_numbers(self, uploaded_file: UploadedFile, expected_mime: str) -> bool:
        """Validate file magic numbers match declared MIME type"""
        if expected_mime not in MAGIC_NUMBER_SIGNATURES:
            return False  # Unknown MIME type

        expected_signatures = MAGIC_NUMBER_SIGNATURES[expected_mime]

        # Text files can have any content, skip magic number validation
        if expected_mime == "text/plain":
            return True

        try:
            uploaded_file.seek(0)
            file_header = uploaded_file.read(32)  # Read first 32 bytes
            uploaded_file.seek(0)

            # Check if file starts with any expected signature
            for signature in expected_signatures:
                if file_header.startswith(signature):
                    return True

            logger.warning(f"🚨 [Ticket Security] Magic number mismatch for MIME {expected_mime}")
            return False

        except Exception as e:
            logger.error(f"🔥 [Ticket Security] Magic number validation failed: {e}")
            return False

    def _validate_file_content(self, uploaded_file: UploadedFile) -> bool:
        """Scan file content for suspicious patterns"""
        try:
            uploaded_file.seek(0)
            # Read first 8KB for content analysis
            content_sample = uploaded_file.read(8192)
            uploaded_file.seek(0)

            # Convert to lowercase for case-insensitive matching
            content_lower = content_sample.lower()

            # Check for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in content_lower:
                    logger.warning(
                        f"🚨 [Ticket Security] Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
                    )
                    return False

            # Additional checks for specific file types
            if b"<html" in content_lower and b"<script" in content_lower:
                logger.warning("🚨 [Ticket Security] HTML with script content detected")
                return False

            return True

        except Exception as e:
            logger.error(f"🔥 [Ticket Security] Content validation failed: {e}")
            return False

    def _reject_file(self, reason: str, filename: str) -> tuple[bool, str]:
        """Log and track file rejection"""
        self.scan_stats["files_rejected"] += 1

        # Track rejection reasons for monitoring
        if reason not in self.scan_stats["rejection_reasons"]:
            self.scan_stats["rejection_reasons"][reason] = 0
        self.scan_stats["rejection_reasons"][reason] += 1

        logger.warning(f"🚨 [Ticket Security] File rejected: {filename} - {reason}")
        return False, reason

    def get_scan_statistics(self) -> ScanStats:
        """Get security scanning statistics for monitoring"""
        return self.scan_stats.copy()


def generate_secure_filename(original_filename: str) -> str:
    """
    🔒 Generate secure filename for storage

    Creates unpredictable filenames to prevent:
    - Direct URL access attempts
    - Information disclosure through filename patterns
    - Path traversal attacks

    Args:
        original_filename: Original uploaded filename

    Returns:
        Secure filename with timestamp and random component
    """
    # Extract safe extension
    file_ext = Path(original_filename).suffix.lower()
    allowed_extensions = set(
        SettingsService.get_list_setting(
            "tickets.allowed_file_extensions", _DEFAULT_ALLOWED_EXTENSIONS
        )
    )
    if file_ext not in allowed_extensions:
        file_ext = ".txt"  # Default to safe extension

    # Generate secure filename: timestamp + random + extension
    timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
    random_component = secrets.token_hex(16)  # 32 character random string

    secure_filename = f"ticket_{timestamp}_{random_component}{file_ext}"

    logger.info(f"🔒 [Ticket Security] Generated secure filename: {original_filename} -> {secure_filename}")
    return secure_filename


def get_secure_upload_path(ticket_id: int, secure_filename: str) -> str:
    """
    🔒 Generate secure upload path for ticket attachments

    Creates directory structure that:
    - Prevents direct web access
    - Organizes files by date for management
    - Uses ticket ID for access control validation

    Args:
        ticket_id: Ticket ID for organization
        secure_filename: Generated secure filename

    Returns:
        Secure upload path relative to MEDIA_ROOT
    """
    # Organize by year/month for management
    current_date = timezone.now()
    year_month = current_date.strftime("%Y/%m")

    # Create path: tickets/attachments/YYYY/MM/ticket_id/filename
    upload_path = f"tickets/attachments/{year_month}/{ticket_id}/{secure_filename}"

    return upload_path
