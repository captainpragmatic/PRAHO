"""URL query preservation for pagination."""

from django.http import HttpRequest


def pagination_query(request: HttpRequest, exclude: tuple[str, ...] = ("page",)) -> str:
    """Return an encoded suffix preserving every non-excluded GET value."""
    parameters = request.GET.copy()
    for key in exclude:
        parameters.pop(key, None)
    encoded = parameters.urlencode()
    return f"&{encoded}" if encoded else ""
