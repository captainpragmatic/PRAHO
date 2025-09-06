# =====# URL Structure:
#   /api/customers/  → Customer management APIs
#   /api/billing/    → Romanian VAT-compliant billing APIs
#   /api/tickets/    → Support tickets API endpoints======================================================================
# PRAHO API MAIN URLS 🚀
# ===============================================================================
#
# Central API routing for all PRAHO domains.
# This file is the single entry point for all API endpoints.
#
# URL Structure:
#   /api/v1/customers/  → Customer management APIs
#   /api/v1/billing/    → Romanian VAT-compliant billing APIs
#   /api/v1/tickets/    → Support ticket & SLA APIs
#
# Architecture:
#   - Centralized routing (like Sentry, Stripe)
#   - Versioned endpoints (v1 currently)
#   - Domain-specific sub-routing
#

from django.urls import path, include
from rest_framework.routers import DefaultRouter

# Import domain-specific URL patterns
from .customers import urls as customer_urls
from .billing import urls as billing_urls  
from .tickets import urls as ticket_urls

app_name = 'api'

# ===============================================================================
# API ROUTING 📍
# ===============================================================================

urlpatterns = [
    # Users & Authentication APIs (for portal service)
    path('users/', include('apps.api.users.urls')),
    
    # Customer Management APIs
    path('customers/', include((customer_urls, 'customers'))),
    
    # Billing & Invoicing APIs (Romanian VAT compliance)
    path('billing/', include((billing_urls, 'billing'))),
    
    # Support Tickets & SLA APIs  
    path('tickets/', include((ticket_urls, 'tickets'))),
    
    # Future API endpoints can be added here:
    # path('domains/', include((domain_urls, 'domains'))),
    # path('provisioning/', include((provisioning_urls, 'provisioning'))),
]

# ===============================================================================
# FUTURE VERSIONS 🔮
# ===============================================================================

# When API versioning is needed, add here:
# urlpatterns += [
#     path('v2/customers/', include((customer_v2_urls, 'customers-v2'))),
#     ...
# ]
