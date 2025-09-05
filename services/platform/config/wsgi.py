"""
WSGI config for PRAHO Platform
"""

import os

from django.core.wsgi import get_wsgi_application

# Set default Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

application = get_wsgi_application()
