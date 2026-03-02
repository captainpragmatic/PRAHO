# ===============================================================================
# SHARED PAGINATION UTILITY - PORTAL SERVICE 📄
# ===============================================================================
# Builds synthetic paginator objects compatible with components/pagination.html.
# Eliminates the ~20-line duplication across ticket, billing, and service views.
# ===============================================================================

from __future__ import annotations


class _Paginator:
    """Minimal paginator matching Django's Paginator interface for template use."""

    __slots__ = ("count", "num_pages", "page_range")

    def __init__(self, count: int, num_pages: int) -> None:
        self.count = count
        self.num_pages = num_pages
        self.page_range = range(1, num_pages + 1)


class PaginatorData:
    """Synthetic page object compatible with components/pagination.html.

    Mirrors the subset of Django's Page interface that the pagination
    template actually uses: has_previous, has_next, number, start_index,
    end_index, previous_page_number, next_page_number, has_other_pages,
    and paginator (with count, num_pages, page_range).
    """

    __slots__ = (
        "_end_index",
        "_start_index",
        "has_next",
        "has_other_pages",
        "has_previous",
        "next_page_number",
        "number",
        "paginator",
        "previous_page_number",
    )

    def __init__(
        self,
        total_count: int,
        current_page: int,
        page_size: int = 25,
    ) -> None:
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        current_page = max(1, min(current_page, total_pages))

        self.number = current_page
        self.has_previous = current_page > 1
        self.has_next = current_page < total_pages
        self.previous_page_number = current_page - 1 if current_page > 1 else 1
        self.next_page_number = current_page + 1
        self.has_other_pages = total_pages > 1
        self.paginator = _Paginator(count=total_count, num_pages=total_pages)

        if total_count > 0:
            self._start_index = (current_page - 1) * page_size + 1
            self._end_index = min(current_page * page_size, total_count)
        else:
            self._start_index = 0
            self._end_index = 0

    @property
    def start_index(self) -> int:
        """Return 1-based start index for the current page."""
        return self._start_index

    @property
    def end_index(self) -> int:
        """Return 1-based end index for the current page."""
        return self._end_index


def build_pagination_params(**filters: str) -> str:
    """Build URL query string from non-empty filter values.

    Usage:
        build_pagination_params(search=search_query, status=status_filter)
        # Returns "&search=foo&status=open" (only non-empty values)
    """
    parts = [f"&{key}={value}" for key, value in filters.items() if value]
    return "".join(parts)
