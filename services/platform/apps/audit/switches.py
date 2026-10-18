"""The one gate for ``DISABLE_AUDIT_SIGNALS`` (ADR-0016).

The flag exists so a test can run a model write without its audit receivers. It is honoured
only while ``settings.TESTING`` is true. Anywhere else it is a misconfiguration that would
silently switch the audit trail off, so it is ignored and shouted about once per process.
"""

from __future__ import annotations

import logging

from django.conf import settings

logger = logging.getLogger(__name__)

_warned = False


def audit_signals_disabled() -> bool:
    """True only when a test has switched the audit receivers off."""
    global _warned  # noqa: PLW0603  # one warning per process, not one per write
    if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return False
    if getattr(settings, "TESTING", False):
        return True
    if not _warned:
        _warned = True
        logger.critical("🔥 [Audit] DISABLE_AUDIT_SIGNALS is set outside of TESTING: ignoring it and auditing anyway")
    return False
