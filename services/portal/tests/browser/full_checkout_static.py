"""The isolated gunicorn fixture has no frontend proxy; serve actual static assets."""

from collections.abc import Callable

from django.conf import settings
from django.contrib.staticfiles.views import serve
from django.http import HttpRequest, HttpResponseBase


class BrowserStaticFilesMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponseBase]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        # Only static assets bypass the application, as the real frontend proxy does.
        # Every auth/session/CSRF/HMAC path keeps the original Portal middleware.
        if request.path.startswith(settings.STATIC_URL):
            return serve(request, request.path[len(settings.STATIC_URL) :])
        return self.get_response(request)
