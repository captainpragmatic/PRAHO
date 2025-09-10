"""
API Client URLs - Proxy endpoints for platform API access
"""

from django.urls import path

from . import views

app_name = 'api_client'

urlpatterns = [
    # Ticket attachment downloads
    path('tickets/<int:ticket_id>/attachments/<int:attachment_id>/download/', 
         views.download_attachment, 
         name='download_attachment'),
]