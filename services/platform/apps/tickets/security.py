"""
🔒 Ticket attachment checks: name, extension, size and format identification.

The format check identifies each file from its own bytes for the extension it carries, so a
file is what its name says: a PDF starts like a PDF, a Word document is a real OOXML package.
There is no content blocklist and no malware scanning: attachments are only ever served as
downloads, never rendered or executed (see ADR-0063).
"""

import codecs
import logging
import secrets
import struct
from pathlib import Path
from typing import TypedDict

from django.core.files.uploadedfile import UploadedFile
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)

# Security constants - configurable via SettingsService
_DEFAULT_MAX_FILE_SIZE_BYTES = 2097152  # 2MB limit
MAX_FILENAME_LENGTH = 255  # Structural - filesystem limit
_DEFAULT_ALLOWED_EXTENSIONS = [".pdf", ".txt", ".png", ".jpg", ".jpeg", ".doc", ".docx"]
MIN_PRINTABLE_CHARACTER = 32

# The only content types an attachment is ever stored with: identify() returns one of these.
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain",
}

PDF_SIGNATURE_WINDOW = 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
JPEG_SOI = b"\xff\xd8\xff"
# A JPEG marker byte after SOI: 0xC0-0xFE (APPn, DQT, SOF, COM, ...); 0xFF is fill and 0x00 is not a marker.
JPEG_MARKER_RANGE = range(0xC0, 0xFF)

# OOXML identification reads only the ZIP central directory and never inflates a member.
ZIP_EOCD = b"PK\x05\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
ZIP64_EOCD = b"PK\x06\x06"
ZIP_CENTRAL_ENTRY = b"PK\x01\x02"
ZIP_EOCD_SIZE = 22
ZIP64_LOCATOR_SIZE = 20
ZIP_MAX_COMMENT = 65535
ZIP_CENTRAL_HEADER_SIZE = 46
ZIP_MAX_16 = 0xFFFF
ZIP_MAX_32 = 0xFFFFFFFF
ZIP_ENCRYPTED_FLAG = 0x1
ZIP_METHODS = frozenset({0, 8})  # stored, deflate
# Real documents with many images stay far below this (measured); more is refused unparsed.
DOCX_MAX_ENTRIES = 20_000
DOCX_REQUIRED = frozenset({"[Content_Types].xml", "word/document.xml"})

TEXT_CHUNK = 64 * 1024
TEXT_ALLOWED_CONTROLS = frozenset({0x09, 0x0A, 0x0C, 0x0D})  # tab, LF, FF, CR
TEXT_MAX_CONTROL_RATIO = 0.01
UTF8_BOM = codecs.BOM_UTF8
UTF16_BOMS = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)


def _read_at(uploaded_file: UploadedFile, offset: int, length: int) -> bytes:
    uploaded_file.seek(offset)
    data = uploaded_file.read(length)
    return data if isinstance(data, bytes) else bytes(data)


def _identify_pdf(uploaded_file: UploadedFile, size: int) -> Result[str, str]:
    if b"%PDF-" in _read_at(uploaded_file, 0, PDF_SIGNATURE_WINDOW):
        return Ok(ALLOWED_TYPES[".pdf"])
    return Err("The file is not a PDF document.")


def _identify_png(uploaded_file: UploadedFile, size: int) -> Result[str, str]:
    header = _read_at(uploaded_file, 0, 16)
    if header[:8] == PNG_SIGNATURE and header[12:16] == b"IHDR":
        return Ok(ALLOWED_TYPES[".png"])
    return Err("The file is not a PNG image.")


def _identify_jpeg(uploaded_file: UploadedFile, size: int) -> Result[str, str]:
    header = _read_at(uploaded_file, 0, 64)
    # JPEG allows 0xFF fill bytes before a marker, so skip them to the first marker byte.
    marker = header[3:].lstrip(b"\xff")[:1]
    if header[:3] == JPEG_SOI and marker and marker[0] in JPEG_MARKER_RANGE:
        return Ok(ALLOWED_TYPES[".jpg"])
    return Err("The file is not a JPEG image.")


def _identify_doc(uploaded_file: UploadedFile, size: int) -> Result[str, str]:
    # Container-level identification: any OLE compound file passes, which is enough for downloads.
    if _read_at(uploaded_file, 0, len(OLE_SIGNATURE)) == OLE_SIGNATURE:
        return Ok(ALLOWED_TYPES[".doc"])
    return Err("The file is not a Word 97-2003 document.")


def _zip_directory(uploaded_file: UploadedFile, size: int) -> Result[tuple[int, int, int], str]:
    """(entries, directory size, directory offset) from the end records, ZIP64 honoured."""
    tail_length = min(size, ZIP_MAX_COMMENT + ZIP_EOCD_SIZE)
    tail = _read_at(uploaded_file, size - tail_length, tail_length)
    # The comment may itself hold the signature: the real record is the one whose declared comment
    # length reaches exactly the end of the file.
    position = tail.rfind(ZIP_EOCD)
    while position >= 0 and (
        len(tail) - position < ZIP_EOCD_SIZE
        or position + ZIP_EOCD_SIZE + struct.unpack_from("<H", tail, position + 20)[0] != len(tail)
    ):
        position = tail.rfind(ZIP_EOCD, 0, position)
    if position < 0:
        return Err("The file is not a Word document.")
    entries, directory_size, directory_offset = struct.unpack_from("<HII", tail, position + 10)
    if entries == ZIP_MAX_16 or ZIP_MAX_32 in (directory_size, directory_offset):
        locator_at = size - tail_length + position - ZIP64_LOCATOR_SIZE
        locator = _read_at(uploaded_file, locator_at, ZIP64_LOCATOR_SIZE) if locator_at >= 0 else b""
        if locator[:4] != ZIP64_LOCATOR:
            return Err("The file is not a Word document.")
        (record_at,) = struct.unpack_from("<Q", locator, 8)
        record = _read_at(uploaded_file, record_at, 56)
        if record[:4] != ZIP64_EOCD or len(record) < 56:  # noqa: PLR2004
            return Err("The file is not a Word document.")
        entries, directory_size, directory_offset = struct.unpack_from("<QQQ", record, 32)
    if entries > DOCX_MAX_ENTRIES:
        return Err("The Word document has too many entries.")
    if directory_offset + directory_size > size:
        return Err("The file is not a Word document.")
    return Ok((entries, directory_size, directory_offset))


def _identify_docx(  # noqa: PLR0911  # Complexity: one refusal per structural check
    uploaded_file: UploadedFile, size: int
) -> Result[str, str]:
    """Identify an OOXML Word package from its central directory alone; its XML is not validated."""
    directory = _zip_directory(uploaded_file, size)
    if directory.is_err():
        return Err(directory.unwrap_err())
    entries, directory_size, directory_offset = directory.unwrap()
    data = _read_at(uploaded_file, directory_offset, directory_size)
    names: set[str] = set()
    offset = 0
    for _index in range(entries):
        header = data[offset : offset + ZIP_CENTRAL_HEADER_SIZE]
        if len(header) < ZIP_CENTRAL_HEADER_SIZE or header[:4] != ZIP_CENTRAL_ENTRY:
            return Err("The file is not a Word document.")
        flags, method = struct.unpack_from("<HH", header, 8)
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
        name = data[offset + ZIP_CENTRAL_HEADER_SIZE : offset + ZIP_CENTRAL_HEADER_SIZE + name_length]
        offset += ZIP_CENTRAL_HEADER_SIZE + name_length + extra_length + comment_length
        if flags & ZIP_ENCRYPTED_FLAG:
            return Err("Encrypted Word documents are not accepted.")
        if method not in ZIP_METHODS:
            return Err("The file is not a Word document.")
        decoded = name.decode("utf-8", errors="replace")
        if decoded in names:
            return Err("The file is not a Word document.")
        names.add(decoded)
    if not DOCX_REQUIRED.issubset(names):
        return Err("The file is not a Word document.")
    return Ok(ALLOWED_TYPES[".docx"])


def _identify_text(uploaded_file: UploadedFile, size: int) -> Result[str, str]:
    """UTF-8 (with or without a BOM), UTF-16 with a BOM, or 8-bit text such as CP1250 logs."""
    uploaded_file.seek(0)
    first = uploaded_file.read(TEXT_CHUNK)
    utf16 = first[:2] in UTF16_BOMS
    decoder = codecs.getincrementaldecoder("utf-16")("strict") if utf16 else None
    characters = controls = 0
    chunk = first
    try:
        while chunk:
            text = decoder.decode(chunk) if decoder else None
            units = (ord(char) for char in text) if text is not None else iter(chunk)
            for unit in units:
                characters += 1
                if unit == 0:
                    return Err("The file is not a text file.")
                if unit < MIN_PRINTABLE_CHARACTER and unit not in TEXT_ALLOWED_CONTROLS:
                    controls += 1
            chunk = uploaded_file.read(TEXT_CHUNK)
        if decoder:
            decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return Err("The file is not a text file.")
    if characters == 0 or controls > characters * TEXT_MAX_CONTROL_RATIO:
        return Err("The file is not a text file.")
    return Ok(ALLOWED_TYPES[".txt"])


_IDENTIFIERS = {
    ".pdf": _identify_pdf,
    ".png": _identify_png,
    ".jpg": _identify_jpeg,
    ".jpeg": _identify_jpeg,
    ".doc": _identify_doc,
    ".docx": _identify_docx,
    ".txt": _identify_text,
}


def identify(uploaded_file: UploadedFile, extension: str) -> Result[str, str]:
    """The allowlisted content type of a file whose bytes match its extension, or why not.

    Only ever returns a value from ALLOWED_TYPES, and leaves the stream where it found it.
    """
    identifier = _IDENTIFIERS.get(extension.lower())
    if identifier is None:
        return Err("This file type is not accepted.")
    position = uploaded_file.tell()
    try:
        return identifier(uploaded_file, uploaded_file.size or 0)
    except (OSError, ValueError, struct.error):
        logger.warning("⚠️ [Ticket Security] Could not read an attachment to identify it", exc_info=True)
        return Err("The file could not be read.")
    finally:
        uploaded_file.seek(position)


class FileSecurityError(Exception):
    """Custom exception for file security violations"""


class ScanStats(TypedDict):
    files_scanned: int
    files_rejected: int
    rejection_reasons: dict[str, int]


class TicketAttachmentSecurityScanner:
    """Checks a ticket attachment's name, extension, size and format before it is stored."""

    def __init__(self) -> None:
        self.scan_stats: ScanStats = {"files_scanned": 0, "files_rejected": 0, "rejection_reasons": {}}
        self.identified_type: str | None = None

    def scan_uploaded_file(self, uploaded_file: UploadedFile, original_filename: str | None = None) -> tuple[bool, str]:
        """(accepted, message). On acceptance, identified_type holds the type to store."""
        self.scan_stats["files_scanned"] += 1
        self.identified_type = None
        filename = original_filename or uploaded_file.name or ""

        if not self._validate_filename(filename):
            return self._reject_file("Invalid filename", filename)
        if not self._validate_file_extension(filename):
            return self._reject_file("Dangerous file extension", filename)
        if not self._validate_file_size(uploaded_file):
            max_file_size = SettingsService.get_integer_setting(
                "tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES
            )
            return self._reject_file(f"File too large ({uploaded_file.size} bytes > {max_file_size})", filename)

        identified = identify(uploaded_file, Path(filename).suffix)
        if identified.is_err():
            return self._reject_file(identified.unwrap_err(), filename)
        self.identified_type = identified.unwrap()
        logger.info(f"✅ [Ticket Security] File security scan passed: {filename}")
        return True, "File security scan passed"

    def _validate_filename(self, filename: str) -> bool:
        """Validate filename for security issues"""
        if not filename or len(filename) > MAX_FILENAME_LENGTH:
            return False

        # Check for path traversal attempts
        if ".." in filename or "/" in filename or "\\" in filename:
            logger.warning(f"🚨 [Ticket Security] Path traversal attempt in filename: {filename!r}")
            return False

        # Control characters, as the API refuses them, and characters no filesystem should see
        suspicious_chars = ["<", ">", ":", '"', "|", "?", "*"]
        if any(ord(char) < MIN_PRINTABLE_CHARACTER for char in filename) or any(
            char in filename for char in suspicious_chars
        ):
            logger.warning(f"🚨 [Ticket Security] Suspicious characters in filename: {filename!r}")
            return False

        return True

    def _validate_file_extension(self, filename: str) -> bool:
        """Validate file extension against allowlist"""
        file_ext = Path(filename).suffix.lower()
        allowed_extensions = set(
            SettingsService.get_list_setting("tickets.allowed_file_extensions", _DEFAULT_ALLOWED_EXTENSIONS)
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
        max_file_size = SettingsService.get_integer_setting("tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES)
        size = uploaded_file.size or 0
        if size > max_file_size:
            logger.warning(f"🚨 [Ticket Security] File too large: {size} bytes")
            return False

        if size == 0:
            logger.warning("🚨 [Ticket Security] Empty file detected")
            return False

        return True

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
        SettingsService.get_list_setting("tickets.allowed_file_extensions", _DEFAULT_ALLOWED_EXTENSIONS)
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
