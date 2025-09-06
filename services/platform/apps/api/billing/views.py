# ===============================================================================
# BILLING API VIEWS - PLACEHOLDER 💰
# ===============================================================================

from apps.api.core import BaseAPIViewSet, ReadOnlyAPIViewSet

# TODO: Add billing API endpoints here
# Examples:
# - InvoiceViewSet for Romanian e-Factura compliant invoices
# - PaymentViewSet for payment processing
# - ProformaViewSet for proforma invoices
# - VATValidationViewSet for CUI validation

class BillingPlaceholderViewSet(ReadOnlyAPIViewSet):
    """Placeholder for future billing API endpoints"""
    
    def get_queryset(self):
        # Placeholder implementation
        return []
