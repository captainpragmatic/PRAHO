# ===============================================================================
# PRAHO PLATFORM API - CENTRALIZED API MODULE 🚀
# ===============================================================================
#
# This app centralizes all API endpoints following the successful pattern
# used by Sentry, Stripe, and other major Django applications.
#
# Structure:
#   - api/core/      → Shared API infrastructure (pagination, permissions, etc.)
#   - api/customers/ → Customer domain API endpoints
#   - api/billing/   → Billing domain API endpoints
#   - api/tickets/   → Support tickets API endpoints
#
# Import Direction (CRITICAL):
#   api → apps.{domain}.services → apps.{domain}.models
#   Never import api modules from domain apps to avoid circular dependencies
#

default_app_config = "apps.api.apps.ApiConfig"
