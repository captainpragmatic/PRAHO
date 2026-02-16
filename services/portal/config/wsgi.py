"""
WSGI config for PRAHO Portal service.
"""

import os

from django.core.wsgi import get_wsgi_application

from config.import_isolation_guard import enforce_portal_import_isolation

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
enforce_portal_import_isolation()

application = get_wsgi_application()
