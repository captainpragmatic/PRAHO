"""Portal URL configuration containing E2E-only positive controls."""

from django.urls import path

from apps.common.e2e_views import csp_violation_positive_control
from config.urls import urlpatterns as portal_urlpatterns

urlpatterns = [
    *portal_urlpatterns,
    path(
        "__e2e__/csp-violation/",
        csp_violation_positive_control,
        name="e2e_csp_violation_positive_control",
    ),
]
