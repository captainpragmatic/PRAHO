"""
WSGI config for PRAHO Platform
"""

import os

from django.core.wsgi import get_wsgi_application

from apps.common.complete_body import require_complete_bodies

# Set default Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

# A body the proxy cut off is an error, never a shorter request (apps/common/complete_body.py).
application = require_complete_bodies(get_wsgi_application())
