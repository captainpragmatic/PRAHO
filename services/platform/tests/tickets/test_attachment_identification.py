"""A ticket attachment's type follows its bytes, never its name, and no content blocklist refuses it.

Attachments are only ever served as downloads, so script or markup inside a log is a normal
support diagnostic, not an attack. What matters is that a file is what its extension says.
"""

import io
import random
import struct
import zipfile
import zlib
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment
from apps.tickets.security import ALLOWED_TYPES, TicketAttachmentSecurityScanner, identify
from apps.users.models import CustomerMembership, User

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Real Word documents with many images stay far below this; a fixture of 20,001 entries is refused.
DOCX_ENTRY_CAP = 20_000


def _upload(name: str, content: bytes) -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content, content_type="application/octet-stream")


def _scan(name: str, content: bytes) -> tuple[bool, str]:
    return TicketAttachmentSecurityScanner().scan_uploaded_file(_upload(name, content), original_filename=name)


def _png(rng: random.Random, payload: int = 6000) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    chunk = struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    noise = bytes(rng.getrandbits(8) for _ in range(payload))
    idat = struct.pack(">I", len(noise)) + b"IDAT" + noise + struct.pack(">I", zlib.crc32(b"IDAT" + noise))
    return PNG_SIGNATURE + chunk + idat


def _docx(rng: random.Random | None = None, extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        archive.writestr("word/document.xml", "<w:document><w:body><w:p>Hello</w:p></w:body></w:document>")
        if rng is not None:
            archive.writestr("word/media/image1.bin", bytes(rng.getrandbits(8) for _ in range(6000)))
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


class IdentificationTests(TestCase):
    def test_an_arbitrary_zip_named_docx_is_refused(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("notes.txt", "not a Word document")

        safe, reason = _scan("report.docx", buffer.getvalue())

        self.assertFalse(safe)
        self.assertIn("Word", reason)

    def test_binary_named_txt_is_refused(self) -> None:
        binary = bytes(range(256)) * 8

        safe, reason = _scan("log.txt", binary)

        self.assertFalse(safe)
        self.assertIn("text", reason)

    def test_a_text_file_with_one_nul_byte_is_refused(self) -> None:
        # Far below the 1% control-byte allowance, so only the NUL rule can refuse it.
        content = b"An ordinary support log line.\n" * 200 + b"\x00" + b"More text.\n"

        safe, reason = _scan("log.txt", content)

        self.assertFalse(safe)
        self.assertEqual(reason, "The file is not a text file.")

    def test_utf8_with_bom_and_multibyte_split_at_1k_is_accepted(self) -> None:
        # The two-byte "ș" straddles the 1 KiB boundary.
        content = b"\xef\xbb\xbf" + b"a" * 1020 + "ș".encode() + "Mulțumesc pentru ajutor.\n".encode() * 50

        self.assertEqual(_scan("notes.txt", content), (True, "File security scan passed"))

    def test_cp1250_and_utf16_logs_are_accepted(self) -> None:
        cp1250 = "Eroare la conexiune: ţară, şampon, ăîâ.\r\n".encode("cp1250") * 40
        utf16 = "Error log ț ș ă\n".encode("utf-16")  # carries its BOM

        for name, content in (("cp1250.txt", cp1250), ("utf16.txt", utf16 * 40)):
            with self.subTest(name=name):
                self.assertEqual(_scan(name, content), (True, "File security scan passed"))

    def test_identify_returns_only_allowlisted_types(self) -> None:
        rng = random.Random(7)  # noqa: S311  # deterministic fixture, not crypto
        samples = {
            ".pdf": b"%PDF-1.7\n1 0 obj\n",
            ".png": _png(rng, 64),
            ".jpg": b"\xff\xd8\xff\xee" + bytes(64),
            ".jpeg": b"\xff\xd8\xff\xe0" + bytes(64),
            ".doc": OLE_SIGNATURE + bytes(64),
            ".docx": _docx(),
            ".txt": b"plain text\n",
        }

        for extension, content in samples.items():
            with self.subTest(extension=extension):
                identified = identify(_upload(f"file{extension}", content), extension)
                self.assertTrue(identified.is_ok(), identified)
                self.assertEqual(identified.unwrap(), ALLOWED_TYPES[extension])
        self.assertTrue(identify(_upload("file.exe", b"MZ"), ".exe").is_err())

    def test_compressed_files_are_not_refused_for_random_bytes(self) -> None:
        rng = random.Random(20261017)  # noqa: S311  # deterministic fixture, not crypto
        refused = []
        for index in range(200):
            for name, content in ((f"shot{index}.png", _png(rng)), (f"doc{index}.docx", _docx(rng))):
                safe, reason = _scan(name, content)
                if not safe:
                    refused.append((name, reason))

        self.assertEqual(refused, [])

    def test_a_php_error_log_txt_is_accepted(self) -> None:
        log = b"PHP Fatal error: Uncaught Error: Call to undefined function exec() in /var/www/index.php:12\n"
        log += b"<?php system($_GET['cmd']); ?>\n<% eval request %>\n"

        self.assertEqual(_scan("php-error.log.txt", log), (True, "File security scan passed"))

    def test_jpeg_marker_variants_are_accepted(self) -> None:
        for marker in (0xE0, 0xE1, 0xDB, 0xEE, 0xC0, 0xFE):
            with self.subTest(marker=hex(marker)):
                self.assertTrue(_scan("photo.jpg", bytes([0xFF, 0xD8, 0xFF, marker]) + bytes(256))[0])
        self.assertFalse(_scan("photo.jpg", b"\xff\xd8\xff\x00" + bytes(256))[0])

    def test_zip_bomb_central_directory_is_never_decompressed(self) -> None:
        bomb = _docx(extra={"word/media/bomb.bin": bytes(8 * 1024 * 1024)})
        self.assertLess(len(bomb), 64 * 1024)

        with (
            patch("zipfile.ZipFile", side_effect=AssertionError("ZipFile constructed")),
            patch("zlib.decompressobj", side_effect=AssertionError("member inflated")),
            patch("zlib.decompress", side_effect=AssertionError("member inflated")),
        ):
            identified = identify(_upload("bomb.docx", bomb), ".docx")

        self.assertTrue(identified.is_ok() or identified.is_err())

    def test_oversized_central_directory_is_refused_before_parsing(self) -> None:
        buffer = io.BytesIO()
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("[Content_Types].xml", "")
            archive.writestr("word/document.xml", "")
            for index in range(DOCX_ENTRY_CAP - 1):
                archive.writestr(alphabet[index // 1296] + alphabet[index // 36 % 36] + alphabet[index % 36], "")
        content = buffer.getvalue()
        self.assertLess(len(content), 2 * 1024 * 1024)

        with patch("zipfile.ZipFile", side_effect=AssertionError("ZipFile constructed")):
            safe, reason = _scan("many.docx", content)

        self.assertFalse(safe)
        self.assertIn("too many entries", reason)

    def test_traversal_in_original_filename_is_refused_for_traversal(self) -> None:
        uploaded = _upload("passwd.txt", b"root:x:0:0\n")

        safe, reason = TicketAttachmentSecurityScanner().scan_uploaded_file(
            uploaded, original_filename="../../../etc/passwd.txt"
        )

        self.assertFalse(safe)
        self.assertEqual(reason, "Invalid filename")

    def test_control_character_filename_is_refused(self) -> None:
        safe, reason = _scan("report\x07.txt", b"hello\n")

        self.assertFalse(safe)
        self.assertEqual(reason, "Invalid filename")

    def test_identification_restores_the_stream_position(self) -> None:
        for name, content in (("ok.pdf", b"%PDF-1.4\n"), ("bad.pdf", b"not a pdf")):
            with self.subTest(name=name):
                uploaded = _upload(name, content)
                uploaded.seek(3)
                identify(uploaded, ".pdf")
                self.assertEqual(uploaded.tell(), 3)


class StaffReplyIdentificationTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Upload Customer", customer_type="business", status="active", primary_email="up@example.test"
        )
        self.user = User.objects.create_user(email="up@example.test", password="testpass123")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="admin")
        self.ticket = Ticket.objects.create(
            customer=self.customer, title="Logs", description="See attached", created_by=self.user
        )
        self.client.login(email="up@example.test", password="testpass123")

    def _reply(self, name: str, content: bytes) -> None:
        self.client.post(
            reverse("tickets:reply", args=[self.ticket.pk]),
            {"reply": "Attached", "attachments": SimpleUploadedFile(name, content, content_type="text/plain")},
        )

    def test_html_in_a_txt_is_accepted_and_served_as_attachment(self) -> None:
        self._reply("page.txt", b"<html><script>alert(1)</script></html>\n")

        attachment = TicketAttachment.objects.get(ticket=self.ticket)
        response = self.client.get(reverse("tickets:download_attachment", args=[attachment.id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(response["Content-Type"], "text/plain")

    def test_the_staff_reply_refuses_a_disguised_file(self) -> None:
        self._reply("invoice.pdf", PNG_SIGNATURE + bytes(64))

        self.assertFalse(TicketAttachment.objects.filter(ticket=self.ticket).exists())
