# ===============================================================================
# BILLING API URLS - PLACEHOLDER 💰
# ===============================================================================

from django.urls import path
from .views import BillingPlaceholderViewSet

app_name = 'billing'

# TODO: Add actual billing API endpoints
urlpatterns = [
    # Placeholder for future billing endpoints
    # path('invoices/', InvoiceViewSet.as_view(), name='invoices'),
    # path('payments/', PaymentViewSet.as_view(), name='payments'),
]
