# ===============================================================================
# TICKETS API VIEWS - PLACEHOLDER 🎫
# ===============================================================================

from apps.api.core import BaseAPIViewSet, ReadOnlyAPIViewSet

# TODO: Add ticket API endpoints here
# Examples:
# - TicketViewSet for support ticket management
# - SLAViewSet for SLA tracking and reporting
# - TicketCategoryViewSet for ticket categorization

class TicketPlaceholderViewSet(ReadOnlyAPIViewSet):
    """Placeholder for future ticket API endpoints"""
    
    def get_queryset(self):
        # Placeholder implementation
        return []
