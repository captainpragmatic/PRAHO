"""Name only test-owned images without replacing another pytest process's references."""

from __future__ import annotations

import os
import re
from functools import lru_cache
from uuid import uuid4

_NAMESPACE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
_REFERENCE = re.compile(r"(praho-[a-z0-9]+(?:-[a-z0-9]+)*):([a-z0-9][a-z0-9_.-]*)", re.ASCII)
_MAX_NAMESPACE_LENGTH = 48
_MAX_NAME_LENGTH = 100
_MAX_TAG_LENGTH = 128


@lru_cache(maxsize=1)
def _process_namespace(process_id: int) -> str:
    # A forked child has a different cache key even if it inherited this module.
    return f"{process_id:x}-{uuid4().hex}"


def fixture_image(reference: str) -> str:
    """Return a private local build target; public/pinned base references never enter here."""
    match = _REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
    if match is None or len(match[1]) > _MAX_NAME_LENGTH or len(match[2]) > _MAX_TAG_LENGTH:
        raise ValueError("A simple test-owned image name and tag are required")
    namespace = os.environ.get("PRAHO_TEST_IMAGE_NAMESPACE")
    if namespace is None:
        namespace = _process_namespace(os.getpid())
    if len(namespace) > _MAX_NAMESPACE_LENGTH or _NAMESPACE.fullmatch(namespace) is None:
        raise ValueError("A valid private test image namespace is required")
    return f"praho-test-{namespace}/{reference}"
