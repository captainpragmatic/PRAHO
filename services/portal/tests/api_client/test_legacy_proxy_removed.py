"""The Portal's legacy attachment proxy is gone; tickets:attachment_download is the one route.

It duplicated the ticket attachment download, was linked from no template, set no `no-store`,
and turned a refused download into a 500.
"""

from __future__ import annotations

import pytest
from django.urls import NoReverseMatch, Resolver404, resolve, reverse


def test_legacy_portal_proxy_route_is_gone() -> None:
    with pytest.raises(NoReverseMatch):
        reverse("api_client:download_attachment", kwargs={"ticket_id": 1, "attachment_id": 2})
    with pytest.raises(Resolver404):
        resolve("/api/tickets/1/attachments/2/download/")
