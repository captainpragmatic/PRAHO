"""
GDPR API endpoints for Portal-to-Platform communication.
Cookie consent, consent history, and data export (GDPR Articles 7, 15, 20).
"""

from django.urls import path

from . import views

urlpatterns = [
    path("cookie-consent/", views.cookie_consent_api, name="gdpr_cookie_consent"),
    path("consent-history/", views.consent_history_api, name="gdpr_consent_history"),
    path("data-export/", views.data_export_api, name="gdpr_data_export"),
]
