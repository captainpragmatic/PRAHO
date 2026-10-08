"""Regression fixtures and the zero-debt contract for status-only assertions."""

from __future__ import annotations

import ast
import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from types import ModuleType
from typing import cast
from unittest.mock import patch

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestAssertionQualityCloseout(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        spec = importlib.util.spec_from_file_location(
            "_assertion_quality_closeout",
            REPO_ROOT / "scripts" / "audit_test_assertion_quality.py",
        )
        assert spec is not None and spec.loader is not None
        self.audit: ModuleType = importlib.util.module_from_spec(spec)
        self.enterContext(patch.dict(sys.modules, {spec.name: self.audit}))
        spec.loader.exec_module(self.audit)

    def _scan(self, source: str) -> list[str]:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "test_sample.py"
            path.write_text(dedent(source), encoding="utf-8")
            scan = cast(Callable[[Path], list[str]], self.audit.scan_file)
            with patch.object(self.audit, "PROJECT_ROOT", root):
                return scan(path)

    def _identity_only(self, source: str) -> bool:
        source = dedent(source)
        function = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef))
        classify = cast(Callable[[list[str], ast.FunctionDef], bool], self.audit._varies_only_identity)
        return classify(source.splitlines(), function)

    def test_mixed_status_membership_is_an_authorisation_result(self) -> None:
        for collection in ("(302, 403)", "[403, 302]", "{302, 403}"):
            with self.subTest(collection=collection):
                source = f"""
                class PermissionTests(TestCase):
                    def test_permission_is_required(self) -> None:
                        response = self.client.get("/protected/")
                        self.assertIn(response.status_code, {collection})
                        Permission.objects.create(codename="view_stats")
                        response = self.client.get("/protected/")
                        self.assertEqual(response.status_code, 200)
                """
                self.assertEqual(self._scan(source), [])

    def test_success_only_membership_still_requires_an_effect(self) -> None:
        for collection in ("(200, 201)", "[200, 204]", "{200, 201}"):
            with self.subTest(collection=collection):
                source = f"""
                class InvoiceTests(TestCase):
                    def test_invoice_is_shown(self) -> None:
                        Invoice.objects.create(number="INV-001")
                        response = self.client.get("/invoices/")
                        self.assertIn(response.status_code, {collection})
                """
                self.assertEqual(
                    self._scan(source),
                    ["test_sample.py::InvoiceTests.test_invoice_is_shown"],
                )

    def test_credential_payload_requires_usable_authenticated_output(self) -> None:
        source = """
        class TokenTests(TestCase):
            def test_returned_token_authenticates(self) -> None:
                response = self.client.post(
                    "/api/users/token/",
                    {"email": self.user.email, "password": self.password},
                )
                self.assertEqual(response.status_code, 200)
                raw_key = response.json()["token"]
                self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")
                info = self.client.get("/api/users/token/me/")
                self.assertEqual(info.status_code, 200)
                self.assertEqual(info.json()["user_id"], self.user.pk)
        """
        self.assertTrue(self._identity_only(source))
        self.assertEqual(self._scan(source), [])

        status_only = """
        class TokenTests(TestCase):
            def test_token_is_issued(self) -> None:
                response = self.client.post(
                    "/api/users/token/",
                    {"email": self.user.email, "password": self.password},
                )
                self.assertEqual(response.status_code, 200)
        """
        self.assertFalse(self._identity_only(status_only))
        self.assertEqual(self._scan(status_only), ["test_sample.py::TokenTests.test_token_is_issued"])

        for changed_source in (
            source.replace('"password": self.password}', '"password": self.password, "ttl_days": 7}'),
            source.replace('"password": self.password}', '"password": self.password, "status": "paid"}'),
            source.replace(
                "response = self.client.post(",
                'Invoice.objects.create(number="INV-001")\n                response = self.client.post(',
            ),
        ):
            with self.subTest(source=changed_source):
                self.assertFalse(self._identity_only(changed_source))

    def test_repository_has_no_status_only_debt(self) -> None:
        scan_all = cast(Callable[[], list[str]], self.audit.scan_all)
        load_baseline = cast(Callable[[Path], set[str]], self.audit.load_baseline)
        self.assertEqual(scan_all(), [])
        self.assertEqual(load_baseline(REPO_ROOT / "scripts" / "status_only_test_baseline.txt"), set())
