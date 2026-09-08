"""CachePanel instrumentation must retain a single wrapper across requests."""

from debug_toolbar.panels.cache import WRAPPED_CACHE_METHODS, CachePanel
from django.core.cache import caches
from django.core.cache.backends.base import BaseCache
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase, override_settings


def _get_response(_request: HttpRequest) -> HttpResponse:
    return HttpResponse()


def _wrapper_depth(method: object) -> int:
    depth = 0
    while True:
        wrapped = getattr(method, "__wrapped__", None)
        if wrapped is None:
            break
        method = wrapped
        depth += 1
    return depth


class CachePanelWrapperTests(SimpleTestCase):
    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "debug-toolbar-cache-panel-tests",
            }
        }
    )
    def test_cache_wrappers_do_not_stack_across_instrumentation_cycles(self) -> None:
        isolated_cache: BaseCache = caches["default"]
        original_methods: dict[str, object] = {
            name: getattr(isolated_cache, name) for name in WRAPPED_CACHE_METHODS
        }

        def restore_cache_methods() -> None:
            for name, method in original_methods.items():
                setattr(isolated_cache, name, method)
            if hasattr(isolated_cache, "_djdt_panel"):
                delattr(isolated_cache, "_djdt_panel")
            isolated_cache.clear()

        self.addCleanup(restore_cache_methods)
        isolated_cache.set("cache-panel-prime", "initialized")
        panel = CachePanel(toolbar=object(), get_response=_get_response)

        try:
            for cycle in range(50):
                panel.enable_instrumentation()
                if cycle == 0:
                    self.assertEqual(_wrapper_depth(isolated_cache.get), 1)
                    isolated_cache.set("cache-panel-round-trip", "enabled")
                    self.assertEqual(isolated_cache.get("cache-panel-round-trip"), "enabled")
                panel.disable_instrumentation()

            isolated_cache.set("cache-panel-round-trip", "disabled")
            self.assertEqual(isolated_cache.get("cache-panel-round-trip"), "disabled")
            self.assertEqual(_wrapper_depth(isolated_cache.get), 1)
        finally:
            if CachePanel.current_instance() is not None:
                panel.disable_instrumentation()
