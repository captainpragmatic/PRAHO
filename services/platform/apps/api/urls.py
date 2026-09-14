# =====# URL Structure:
#   /api/customers/  → Customer management APIs
#   /api/billing/    → Romanian VAT-compliant billing APIs
#   /api/tickets/    → Support tickets API endpoints
#   /api/services/   → Customer hosting services APIs
# ===============================================================================
# PRAHO API MAIN URLS 🚀
# ===============================================================================
#
# Central API routing for all PRAHO domains.
# This file is the single entry point for all API endpoints.
#
# URL Structure:
#   /api/customers/  → Customer management APIs
#   /api/billing/    → Romanian VAT-compliant billing APIs
#   /api/tickets/    → Support ticket & SLA APIs
#   /api/services/   → Customer hosting services APIs
#
# Architecture:
#   - Centralized routing (like Sentry, Stripe)
#   - Domain-specific sub-routing
#   - Future versioning ready
#

from django.urls import include, path

from .billing import urls as billing_urls

# Import domain-specific URL patterns
from .customers import urls as customer_urls
from .localisation.views import localisation_defaults
from .orders import urls as order_urls
from .services import urls as services_urls
from .tickets import urls as ticket_urls

app_name = "api"

# ===============================================================================
# API ROUTING 📍
# ===============================================================================

urlpatterns = [
    path("localisation/", localisation_defaults, name="localisation"),
    # Users & Authentication APIs (for portal service)
    path("users/", include("apps.api.users.urls")),
    # Customer Management APIs
    path("customers/", include((customer_urls, "customers"))),
    # Billing & Invoicing APIs (Romanian VAT compliance)
    path("billing/", include((billing_urls, "billing"))),
    # Support Tickets & SLA APIs
    path("tickets/", include((ticket_urls, "tickets"))),
    # Services & Hosting APIs
    path("services/", include((services_urls, "services"))),
    # Orders & Product Catalog APIs
    path("orders/", include((order_urls, "orders"))),
    # GDPR compliance APIs (cookie consent, consent history, data export)
    path("gdpr/", include("apps.api.gdpr.urls")),
]

# ===============================================================================
# FUTURE VERSIONS 🔮
# ===============================================================================

# When API versioning is needed, add here:
# urlpatterns += [...] for v2 endpoints
