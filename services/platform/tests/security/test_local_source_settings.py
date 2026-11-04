"""The actual deployed settings module, not an environment hint, authorizes local staging RPC."""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = """import django,sys
django.setup()
from django.core.exceptions import ValidationError
from apps.security.models import SecuritySource
from apps.security.transport import bind_connection
from uuid import uuid4
source=SecuritySource(kind='portal',transport='local',hostname='localhost',port=0,host_keys='',installation_id=uuid4(),configuration_digest='a'*64)
try:
 bind_connection(source)
except ValidationError:
 admitted=False
else:
 admitted=True
assert admitted == (sys.argv[1] == 'staging'), 'Deployed settings authorize the wrong local source environment'
"""


@pytest.mark.parametrize("environment", ["staging", "prod"])
def test_deployed_settings_admit_local_source_only_in_staging(environment: str, tmp_path: Path) -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "TMPDIR", "LANG", "LC_ALL", "HOME"}
    }
    env.update(
        {
            "PRAHO_SKIP_DOTENV": "1",
            "DJANGO_SETTINGS_MODULE": f"config.settings.{environment}",
            "ENVIRONMENT": "staging",
            "PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED": "true",
            "DJANGO_SECRET_KEY": secrets.token_urlsafe(64),
            "DB_PASSWORD": secrets.token_urlsafe(32),
            "HMAC_SECRET": secrets.token_urlsafe(64),
            "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": secrets.token_urlsafe(64),
            "PLATFORM_DOMAIN": "platform.example.test",
            "PORTAL_DOMAIN": "portal.example.test",
            "ALLOWED_HOSTS": "platform.example.test,portal.example.test,localhost",
            "PLATFORM_LOG_DIR": str(tmp_path),
            "PORTAL_HMAC_CREDENTIALS": json.dumps({"fixture-portal": secrets.token_urlsafe(64)}),
            "DJANGO_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            "CREDENTIAL_VAULT_MASTER_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            "COMPANY_NAME": "Qualified Fixture",
            "COMPANY_CUI": "IE1234567",
            "COMPANY_COUNTRY_CODE": "IE",
            "DEFAULT_FROM_EMAIL": "fixture@example.test",
            "TIME_ZONE": "Europe/Dublin",
        }
    )
    result = subprocess.run(  # noqa: S603 -- fixed interpreter/program and isolated nonsecret fixture configuration
        [sys.executable, "-c", SCRIPT, environment], env=env, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr[-4000:]
