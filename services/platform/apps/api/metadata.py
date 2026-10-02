"""OPTIONS metadata for the Platform API (#567)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rest_framework.metadata import SimpleMetadata

if TYPE_CHECKING:
    # Annotation-only. DRF resolves DEFAULT_METADATA_CLASS while rest_framework.views is
    # still being defined, so importing APIView here at runtime is a circular import.
    from rest_framework.request import Request
    from rest_framework.views import APIView


class NoDocstringMetadata(SimpleMetadata):  # type: ignore[misc]  # DRF metadata base is untyped
    """DRF's SimpleMetadata without the view docstring.

    SimpleMetadata returns the view docstring as "description" on every OPTIONS request.
    Public endpoints answer OPTIONS unauthenticated, and their docstrings are written for
    maintainers (``obtain_token``'s is a full request and response contract). Nothing
    consumes the description, so it is not published at all.
    """

    def determine_metadata(self, request: Request, view: APIView) -> dict[str, Any]:
        metadata = dict(super().determine_metadata(request, view))
        metadata.pop("description", None)
        return metadata
