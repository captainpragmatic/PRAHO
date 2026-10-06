"""The pagination query API preserves QueryDict semantics."""

from importlib import import_module
from importlib.util import find_spec
from typing import Protocol, cast
from urllib.parse import parse_qs

from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase

from tests.common.pagination_assertions import SEARCH


class _PaginationQuery(Protocol):
    def __call__(self, request: HttpRequest, exclude: tuple[str, ...] = ("page",)) -> str: ...


class PaginationQueryTests(SimpleTestCase):
    def query(self, request: HttpRequest, exclude: tuple[str, ...] = ("page",)) -> str:
        self.assertIsNotNone(find_spec("apps.common.pagination"), "Pagination helper module must exist")
        helper = getattr(import_module("apps.common.pagination"), "pagination_query", None)
        self.assertTrue(callable(helper), "pagination_query must be callable")
        return cast(_PaginationQuery, helper)(request, exclude=exclude)

    def test_multivalued_keys_round_trip_without_mutating_get(self) -> None:
        request = RequestFactory().get(
            "/", {"q": SEARCH, "status": ["active", "pending"], "empty": "", "literal": "50% off"}
        )
        before = list(request.GET.lists())
        result = self.query(request)
        self.assertTrue(result.startswith("&"))
        self.assertEqual(
            parse_qs(result[1:], keep_blank_values=True),
            {"q": [SEARCH], "status": ["active", "pending"], "empty": [""], "literal": ["50% off"]},
        )
        self.assertEqual(list(request.GET.lists()), before)

    def test_all_page_values_are_excluded(self) -> None:
        request = RequestFactory().get("/", {"page": ["1", "9"], "q": SEARCH})
        self.assertEqual(self.query(request), "&q=a%26b+c%2Bd%23e")
        self.assertEqual(request.GET.getlist("page"), ["1", "9"])

    def test_empty_and_page_only_queries_return_empty_string(self) -> None:
        for parameters in ({}, {"page": ["1", "9"]}):
            with self.subTest(parameters=parameters):
                self.assertEqual(self.query(RequestFactory().get("/", parameters)), "")

    def test_custom_exclusions_keep_the_default_page_key_when_not_excluded(self) -> None:
        request = RequestFactory().get("/", {"page": "1", "cursor": ["old", "new"], "q": SEARCH})
        self.assertEqual(
            parse_qs(self.query(request, exclude=("cursor",))[1:]),
            {"page": ["1"], "q": [SEARCH]},
        )
