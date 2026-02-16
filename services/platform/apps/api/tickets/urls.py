# ===============================================================================
# TICKETS API URLS - CUSTOMER SUPPORT OPERATIONS 🎫
# ===============================================================================

from django.urls import path

from .views import (
    customer_ticket_create_api,
    customer_ticket_detail_api,
    customer_ticket_reply_api,
    customer_tickets_api,
    customer_tickets_summary_api,
    support_categories_api,
    ticket_attachment_download_api,
)

app_name = "tickets"

urlpatterns = [
    # Customer tickets endpoints
    path("", customer_tickets_api, name="customer_tickets_list"),
    path("summary/", customer_tickets_summary_api, name="customer_tickets_summary"),
    path("categories/", support_categories_api, name="support_categories"),
    path("create/", customer_ticket_create_api, name="customer_ticket_create"),
    # Individual ticket endpoints
    path("<int:ticket_id>/", customer_ticket_detail_api, name="customer_ticket_detail"),
    path("<int:ticket_id>/reply/", customer_ticket_reply_api, name="customer_ticket_reply"),
    path(
        "<int:ticket_id>/attachments/<int:attachment_id>/download/",
        ticket_attachment_download_api,
        name="ticket_attachment_download",
    ),
]
