"""
===============================================================================
📄 PAGINATION UTILITIES - PRAHO Platform
===============================================================================
Simple, reusable pagination utilities for consistent pagination behavior.

Features:
- ✅ Consistent 20 items per page
- ✅ Preserves query parameters
- ✅ Romanian business-friendly pagination
- ✅ Easy integration with existing views
===============================================================================
"""

from typing import Any, TypeVar

from django.core.paginator import Paginator
from django.db.models import Model, Q, QuerySet
from django.http import HttpRequest

# Generic type variable for model instances
T = TypeVar("T", bound=Model)

# 🎯 Romanian business pagination constants
DEFAULT_PAGE_SIZE = 20
DEFAULT_ORPHANS = 3


def get_pagination_context(
    request: HttpRequest,
    queryset: QuerySet[T],
    page_size: int = DEFAULT_PAGE_SIZE,
    page_param: str = "page",
    orphans: int = DEFAULT_ORPHANS,
) -> dict[str, Any]:
    """
    📄 Get pagination context for any Django view

    Simple utility function that can be used in any view to add pagination.
    Follows Romanian business practices with sensible defaults.

    Usage in views:
        def billing_list(request):
            invoices = Invoice.objects.filter(customer=request.user.customer)

            context = get_pagination_context(
                request=request,
                queryset=invoices,
                page_size=20
            )

            return render(request, 'billing/list.html', context)

    Args:
        request: Django HttpRequest object
        queryset: QuerySet to paginate
        page_size: Items per page (default: 20)
        page_param: URL parameter name for page (default: 'page')
        orphans: Minimum items for last page (default: 3)

    Returns:
        Dict with pagination context for templates:
        - page_obj: Paginated page object
        - is_paginated: Whether pagination is active
        - query_params: Preserved URL parameters
        - paginator: Django paginator object
    """

    # Create paginator
    paginator = Paginator(queryset, page_size, orphans=orphans)

    # Get current page number
    page_number = request.GET.get(page_param, 1)
    page_obj = paginator.get_page(page_number)

    # Build preserved query parameters (exclude page parameter)
    query_params = request.GET.copy()
    if page_param in query_params:
        del query_params[page_param]

    preserved_params = "&" + query_params.urlencode() if query_params else ""

    return {
        "page_obj": page_obj,
        "is_paginated": page_obj.has_other_pages(),
        "paginator": paginator,
        "extra_params": preserved_params,
    }


def get_search_context(request: HttpRequest, search_param: str = "search") -> dict[str, Any]:
    """
    📄 Get search context for templates

    Utility to extract and provide search context for templates.

    Args:
        request: Django HttpRequest object
        search_param: URL parameter name for search (default: 'search')

    Returns:
        Dict with search context
    """
    search_query = request.GET.get(search_param, "").strip()

    return {
        "search_query": search_query,
        "search_param": search_param,
        "has_search": bool(search_query),
    }


def filter_queryset_by_search(queryset: QuerySet[T], search_query: str, search_fields: list[str]) -> QuerySet[T]:
    """
    📄 Filter queryset by search terms

    Utility to apply search filtering to any queryset.

    Args:
        queryset: Django QuerySet to filter
        search_query: Search term string
        search_fields: List of model fields to search in

    Returns:
        Filtered QuerySet
    """
    if not search_query or not search_fields:
        return queryset

    # Build search filter
    search_filter = Q()
    for field in search_fields:
        search_filter |= Q(**{f"{field}__icontains": search_query})

    return queryset.filter(search_filter)


class PaginationMixin:
    """
    📄 Simple mixin for Django class-based views

    Provides basic pagination functionality. Use this for ListView subclasses.

    Usage:
        class InvoiceListView(PaginationMixin, ListView):
            model = Invoice
            template_name = 'billing/list.html'
            paginate_by = 20  # Optional override
    """

    paginate_by = DEFAULT_PAGE_SIZE
    paginate_orphans = DEFAULT_ORPHANS

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add pagination context to template"""
        context = super().get_context_data(**kwargs)  # type: ignore

        # Add preserved query parameters for pagination links
        if hasattr(self, "request"):
            query_params = self.request.GET.copy()
            if "page" in query_params:
                del query_params["page"]
            context["extra_params"] = "&" + query_params.urlencode() if query_params else ""

        return context
