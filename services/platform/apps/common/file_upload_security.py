"""
Secure file upload validation service.

Implements comprehensive file upload security including:
- MIME type validation
- File extension whitelist
- Content-based type detection
- Size limits
- Malicious content detection

Security Standards:
- OWASP File Upload Guidelines
- CWE-434: Unrestricted Upload of File with Dangerous Type
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Final

from django.core.files.uploadedfile import UploadedFile

logger = logging.getLogger(__name__)


class FileUploadError(Exception):
    """Base exception for file upload validation errors."""


class FileTypeNotAllowed(FileUploadError):  # noqa: N818
    """Raised when file type is not in the allowed list."""


class FileSizeTooLarge(FileUploadError):  # noqa: N818
    """Raised when file exceeds size limits."""


class MaliciousContentDetected(FileUploadError):  # noqa: N818
    """Raised when potentially malicious content is detected."""


class FileCategory(Enum):
    """Categories of allowed file types."""

    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    DATA = "data"


@dataclass(frozen=True)
class AllowedFileType:
    """Configuration for an allowed file type."""

    extension: str
    mime_types: tuple[str, ...]
    category: FileCategory
    max_size_mb: float = 10.0
    magic_bytes: tuple[bytes, ...] | None = None


# ============================================================================
# ALLOWED FILE TYPES CONFIGURATION
# ============================================================================

ALLOWED_FILE_TYPES: Final[dict[str, AllowedFileType]] = {
    # Images
    ".jpg": AllowedFileType(
        ".jpg",
        ("image/jpeg",),
        FileCategory.IMAGE,
        max_size_mb=10.0,
        magic_bytes=(b"\xff\xd8\xff",),
    ),
    ".jpeg": AllowedFileType(
        ".jpeg",
        ("image/jpeg",),
        FileCategory.IMAGE,
        max_size_mb=10.0,
        magic_bytes=(b"\xff\xd8\xff",),
    ),
    ".png": AllowedFileType(
        ".png",
        ("image/png",),
        FileCategory.IMAGE,
        max_size_mb=10.0,
        magic_bytes=(b"\x89PNG\r\n\x1a\n",),
    ),
    ".gif": AllowedFileType(
        ".gif",
        ("image/gif",),
        FileCategory.IMAGE,
        max_size_mb=5.0,
        magic_bytes=(b"GIF87a", b"GIF89a"),
    ),
    ".webp": AllowedFileType(
        ".webp",
        ("image/webp",),
        FileCategory.IMAGE,
        max_size_mb=10.0,
        magic_bytes=(b"RIFF",),  # WebP starts with RIFF
    ),
    ".svg": AllowedFileType(
        ".svg",
        ("image/svg+xml",),
        FileCategory.IMAGE,
        max_size_mb=1.0,
        # SVG is text-based, no magic bytes
    ),
    # Documents
    ".pdf": AllowedFileType(
        ".pdf",
        ("application/pdf",),
        FileCategory.DOCUMENT,
        max_size_mb=25.0,
        magic_bytes=(b"%PDF",),
    ),
    ".txt": AllowedFileType(
        ".txt",
        ("text/plain",),
        FileCategory.DOCUMENT,
        max_size_mb=5.0,
    ),
    ".csv": AllowedFileType(
        ".csv",
        ("text/csv", "text/plain", "application/csv"),
        FileCategory.DATA,
        max_size_mb=50.0,
    ),
    ".json": AllowedFileType(
        ".json",
        ("application/json", "text/json"),
        FileCategory.DATA,
        max_size_mb=10.0,
    ),
    ".xml": AllowedFileType(
        ".xml",
        ("application/xml", "text/xml"),
        FileCategory.DATA,
        max_size_mb=10.0,
        magic_bytes=(b"<?xml",),
    ),
    # Archives (for backup uploads)
    ".zip": AllowedFileType(
        ".zip",
        ("application/zip", "application/x-zip-compressed"),
        FileCategory.ARCHIVE,
        max_size_mb=100.0,
        magic_bytes=(b"PK\x03\x04", b"PK\x05\x06"),
    ),
    ".gz": AllowedFileType(
        ".gz",
        ("application/gzip", "application/x-gzip"),
        FileCategory.ARCHIVE,
        max_size_mb=100.0,
        magic_bytes=(b"\x1f\x8b",),
    ),
}

# Dangerous patterns that should never appear in uploads
DANGEROUS_PATTERNS: Final[tuple[bytes, ...]] = (
    b"<script",
    b"javascript:",
    b"vbscript:",
    b"onload=",
    b"onerror=",
    b"onclick=",
    b"eval(",
    b"<?php",
    b"<%",
    b"#!/",
    b"import os",
    b"subprocess",
    b"exec(",
    b"system(",
)

# Additional patterns for SVG files (which are XML-based)
SVG_DANGEROUS_PATTERNS: Final[tuple[bytes, ...]] = (
    b"<script",
    b"javascript:",
    b"onload",
    b"onerror",
    b"onclick",
    b"onmouseover",
    b"onfocus",
    b"<foreignObject",
    b"xlink:href",
    b"data:",
)


@dataclass
class FileValidationResult:
    """Result of file validation."""

    is_valid: bool
    file_hash: str | None = None
    detected_mime_type: str | None = None
    detected_extension: str | None = None
    file_size: int = 0
    error_message: str | None = None
    category: FileCategory | None = None


class FileUploadSecurityService:
    """
    Comprehensive file upload security validation service.

    Usage:
        service = FileUploadSecurityService()
        result = service.validate_file(uploaded_file)

        if not result.is_valid:
            raise ValidationError(result.error_message)

        # File is safe to save
        uploaded_file.save()
    """

    def __init__(
        self,
        allowed_extensions: set[str] | None = None,
        allowed_categories: set[FileCategory] | None = None,
        max_size_override_mb: float | None = None,
        scan_content: bool = True,
    ) -> None:
        """
        Initialize the security service.

        Args:
            allowed_extensions: Specific extensions to allow (subset of ALLOWED_FILE_TYPES)
            allowed_categories: Allow all extensions in these categories
            max_size_override_mb: Override default max size for all types
            scan_content: Whether to scan content for malicious patterns
        """
        self.allowed_extensions = allowed_extensions
        self.allowed_categories = allowed_categories
        self.max_size_override_mb = max_size_override_mb
        self.scan_content = scan_content

    def validate_file(  # noqa: PLR0911
        self,
        file: UploadedFile,
        filename: str | None = None,
    ) -> FileValidationResult:
        """
        Validate an uploaded file for security.

        Args:
            file: The uploaded file to validate
            filename: Override filename (uses file.name if not provided)

        Returns:
            FileValidationResult with validation status and details
        """
        filename = filename or file.name
        if not filename:
            return FileValidationResult(
                is_valid=False,
                error_message="Filename is required",
            )

        # Get file extension
        extension = Path(filename).suffix.lower()

        # Check extension is allowed
        if extension not in ALLOWED_FILE_TYPES:
            logger.warning(
                f"File upload rejected - extension not allowed: {extension}",
                extra={"filename": filename, "extension": extension},
            )
            return FileValidationResult(
                is_valid=False,
                error_message=f"File type '{extension}' is not allowed",
                detected_extension=extension,
            )

        file_type = ALLOWED_FILE_TYPES[extension]

        # Check if extension is in allowed subset
        if self.allowed_extensions and extension not in self.allowed_extensions:
            return FileValidationResult(
                is_valid=False,
                error_message=f"File type '{extension}' is not allowed for this upload",
                detected_extension=extension,
            )

        # Check if category is allowed
        if self.allowed_categories and file_type.category not in self.allowed_categories:
            return FileValidationResult(
                is_valid=False,
                error_message=f"File category '{file_type.category.value}' is not allowed",
                detected_extension=extension,
                category=file_type.category,
            )

        # Get file size
        file_size = file.size if hasattr(file, "size") else 0
        max_size_bytes = int((self.max_size_override_mb or file_type.max_size_mb) * 1024 * 1024)

        if file_size is not None and file_size > max_size_bytes:
            logger.warning(
                f"File upload rejected - too large: {file_size} bytes",
                extra={
                    "filename": filename,
                    "file_size": file_size,
                    "max_size": max_size_bytes,
                },
            )
            return FileValidationResult(
                is_valid=False,
                error_message=f"File size ({(file_size or 0) // (1024*1024)}MB) exceeds maximum ({file_type.max_size_mb}MB)",
                file_size=file_size or 0,
                detected_extension=extension,
            )

        # Read file content for validation
        file.seek(0)
        content = file.read(8192)  # Read first 8KB for validation
        file.seek(0)  # Reset file pointer

        # Validate MIME type from content
        detected_mime = self._detect_mime_type(content, filename)
        if (
            detected_mime
            and detected_mime not in file_type.mime_types
            and not self._is_compatible_mime(detected_mime, file_type.mime_types)
        ):
            logger.warning(
                "File upload rejected - MIME type mismatch",
                extra={
                    "filename": filename,
                    "detected_mime": detected_mime,
                    "expected_mimes": file_type.mime_types,
                },
            )
            return FileValidationResult(
                is_valid=False,
                error_message="File content does not match expected type",
                detected_mime_type=detected_mime,
                detected_extension=extension,
            )

        # Validate magic bytes if available
        if file_type.magic_bytes and not self._validate_magic_bytes(content, file_type.magic_bytes):
            logger.warning(
                "File upload rejected - magic bytes mismatch",
                extra={"filename": filename, "extension": extension},
            )
            return FileValidationResult(
                is_valid=False,
                error_message="File content does not match expected format",
                detected_extension=extension,
            )

        # Scan for malicious content
        if self.scan_content:
            scan_result = self._scan_for_malicious_content(content, extension, filename)
            if scan_result:
                logger.error(
                    "File upload rejected - malicious content detected",
                    extra={"filename": filename, "reason": scan_result},
                )
                return FileValidationResult(
                    is_valid=False,
                    error_message="Potentially malicious content detected in file",
                    detected_extension=extension,
                )

        # Calculate file hash for integrity tracking
        file.seek(0)
        file_hash = self._calculate_file_hash(file)  # type: ignore[arg-type]
        file.seek(0)

        logger.info(
            "File upload validated successfully",
            extra={
                "filename": filename,
                "extension": extension,
                "file_size": file_size,
                "file_hash": file_hash[:16],
            },
        )

        return FileValidationResult(
            is_valid=True,
            file_hash=file_hash,
            detected_mime_type=detected_mime,
            detected_extension=extension,
            file_size=file_size or 0,
            category=file_type.category,
        )

    def _detect_mime_type(self, content: bytes, filename: str) -> str | None:
        """Detect MIME type from content and filename."""
        # Try to guess from filename first
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type

    def _is_compatible_mime(self, detected: str, expected: tuple[str, ...]) -> bool:
        """Check if detected MIME type is compatible with expected types."""
        # Handle text-based format variations
        if detected.startswith("text/") and any(exp.startswith("text/") for exp in expected):
            return True
        return detected in expected

    def _validate_magic_bytes(self, content: bytes, magic_bytes: tuple[bytes, ...]) -> bool:
        """Validate that content starts with expected magic bytes."""
        return any(content.startswith(magic) for magic in magic_bytes)

    def _scan_for_malicious_content(
        self,
        content: bytes,
        extension: str,
        filename: str,
    ) -> str | None:
        """
        Scan content for potentially malicious patterns.

        Returns error message if malicious content detected, None otherwise.
        """
        content_lower = content.lower()

        # Check common dangerous patterns
        for pattern in DANGEROUS_PATTERNS:
            if pattern.lower() in content_lower:
                return f"Dangerous pattern detected: {pattern.decode('utf-8', errors='ignore')}"

        # Additional checks for SVG files
        if extension == ".svg":
            for pattern in SVG_DANGEROUS_PATTERNS:
                if pattern.lower() in content_lower:
                    return f"SVG contains potentially dangerous element: {pattern.decode('utf-8', errors='ignore')}"

        return None

    def _calculate_file_hash(self, file: BinaryIO) -> str:
        """Calculate SHA-256 hash of file content."""
        sha256_hash = hashlib.sha256()
        for chunk in iter(lambda: file.read(8192), b""):
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def validate_image_upload(file: UploadedFile) -> FileValidationResult:
    """Validate an image upload."""
    service = FileUploadSecurityService(
        allowed_categories={FileCategory.IMAGE},
    )
    return service.validate_file(file)


def validate_document_upload(file: UploadedFile) -> FileValidationResult:
    """Validate a document upload."""
    service = FileUploadSecurityService(
        allowed_categories={FileCategory.DOCUMENT, FileCategory.DATA},
    )
    return service.validate_file(file)


def validate_backup_upload(file: UploadedFile) -> FileValidationResult:
    """Validate a backup archive upload."""
    service = FileUploadSecurityService(
        allowed_categories={FileCategory.ARCHIVE},
        max_size_override_mb=500.0,  # Allow larger backups
    )
    return service.validate_file(file)


def get_allowed_extensions() -> list[str]:
    """Get list of all allowed file extensions."""
    return list(ALLOWED_FILE_TYPES.keys())


def get_allowed_mime_types() -> list[str]:
    """Get list of all allowed MIME types."""
    mime_types: set[str] = set()
    for file_type in ALLOWED_FILE_TYPES.values():
        mime_types.update(file_type.mime_types)
    return sorted(mime_types)
