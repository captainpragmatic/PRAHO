# ===============================================================================
# API PAGINATION CLASSES 📄
# ===============================================================================

from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination for PRAHO API endpoints.
    Consistent page sizes across all API responses.
    """

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100
