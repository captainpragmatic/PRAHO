"""
WSGI config for PRAHO Portal service.
"""

import os

from django.core.wsgi import get_wsgi_application

from apps.common.complete_body import require_complete_bodies
from config.import_isolation_guard import enforce_portal_import_isolation

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")
enforce_portal_import_isolation()

# A body the proxy cut off is an error, never a shorter request (apps/common/complete_body.py).
application = require_complete_bodies(get_wsgi_application())
