"""
API Client Views - Proxy views for platform API access
"""

import logging
import re
import time

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect

from .services import platform_api

logger = logging.getLogger(__name__)


def download_attachment(
    request: HttpRequest, ticket_id: int, attachment_id: int
) -> HttpResponse | HttpResponseRedirect:
    """
    Proxy attachment download requests to platform service.
    """
    # Check authentication via Django session
    customer_id = request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        # Build request data for HMAC authentication

        request_data = {
            "customer_id": customer_id,
            "user_id": user_id,
            "ticket_id": ticket_id,
            "attachment_id": attachment_id,
            "action": "download_attachment",
            "timestamp": time.time(),
        }

        # Use platform API client to get both content and headers
        content, headers = platform_api._make_binary_request_with_headers(
            "POST", f"/tickets/{ticket_id}/attachments/{attachment_id}/download/", data=request_data
        )

        # Extract filename from Content-Disposition header
        content_disposition = headers.get("Content-Disposition", "")
        filename = f"attachment_{attachment_id}"  # Default fallback

        if content_disposition:
            # Parse Content-Disposition header to extract filename
            filename_match = re.search(r'filename="([^"]+)"', content_disposition)
            if filename_match:
                filename = filename_match.group(1)
            else:
                # Try without quotes
                filename_match = re.search(r"filename=([^;]+)", content_disposition)
                if filename_match:
                    filename = filename_match.group(1).strip()

        logger.info(f"✅ [API Proxy] Downloaded attachment: {filename} (ID: {attachment_id})")

        # Create HTTP response with proper headers
        content_type = headers.get("Content-Type", "application/octet-stream")
        http_response = HttpResponse(content, content_type=content_type)
        http_response["Content-Disposition"] = f'attachment; filename="{filename}"'

        return http_response

    except Exception as e:
        logger.error(f"🔥 [API Proxy] Error downloading attachment {attachment_id} for ticket {ticket_id}: {e}")
        return HttpResponse("Download failed", status=500)
