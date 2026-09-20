# ===============================================================================
# CUSTOMER TICKETS URLS - PORTAL SERVICE 🎫
# ===============================================================================

from django.urls import path

from . import views

app_name = "tickets"

urlpatterns = [
    # Main ticket views
    path("", views.ticket_list, name="list"),
    path("create/", views.ticket_create, name="create"),
    path("<int:ticket_id>/", views.ticket_detail, name="detail"),
    path(
        "<int:ticket_id>/attachments/<int:attachment_id>/download/",
        views.ticket_attachment_download,
        name="attachment_download",
    ),
    # HTMX endpoints
    path("<int:ticket_id>/reply/", views.ticket_reply, name="reply"),
    path("search/", views.ticket_search_api, name="search_api"),
    # Dashboard widget
    path("widget/", views.tickets_dashboard_widget, name="dashboard_widget"),
]
