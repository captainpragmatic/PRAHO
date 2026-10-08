"""Coverage additions for the existing common pagination adapters."""

from django.http import HttpResponse
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase
from django.views.generic import ListView

from apps.common.mixins import PaginationMixin, get_pagination_context
from apps.customers.models import Customer
from tests.common.pagination_assertions import SEARCH, assert_next_query


class _CustomerList(PaginationMixin, ListView):
    model = Customer
    paginate_by = 2
    paginate_orphans = 0


class PaginationBuilderTests(TestCase):
    def setUp(self) -> None:
        for number in range(3):
            Customer.objects.create(name=f"Paging {number}", primary_email=f"paging-{number}@example.test")
        self.request = RequestFactory().get("/", {"q": SEARCH, "status": ["active", "pending"], "page": ["9", "1"]})

    def test_function_context_round_trips_repeated_filters(self) -> None:
        context = get_pagination_context(self.request, Customer.objects.order_by("pk"), page_size=2, orphans=0)
        response = HttpResponse(render_to_string("components/pagination.html", context))
        assert_next_query(self, response, {"q": [SEARCH], "status": ["active", "pending"]})

    def test_mixin_context_round_trips_repeated_filters(self) -> None:
        view = _CustomerList()
        view.setup(self.request)
        view.object_list = Customer.objects.order_by("pk")
        response = HttpResponse(render_to_string("components/pagination.html", view.get_context_data()))
        assert_next_query(self, response, {"q": [SEARCH], "status": ["active", "pending"]})
