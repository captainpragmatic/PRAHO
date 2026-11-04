"""Native trust and outbound settings reach the actual Django configuration."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("profile", ["prod", "staging"])
def test_platform_reads_explicit_native_local_proxy_and_callback_domain(profile: str) -> None:
    environment = {**os.environ, "PLATFORM_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
                   "INTERNAL_SERVICE_ALLOWED_DOMAINS": "portal.example.test", "PRAHO_SKIP_DOTENV": "1",
                   "SENTRY_DSN": "", "REDIS_URL": "", "DJANGO_SECRET_KEY": "s" * 64, "HMAC_SECRET": "h" * 64, "DB_PASSWORD": "fixture-database-password-unique",
                   "DJANGO_ENCRYPTION_KEY": "a" * 43 + "=", "CREDENTIAL_VAULT_MASTER_KEY": "a" * 43 + "=",
                   "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": "w" * 64, "ALLOWED_HOSTS": "staff.example.test",
                   "PORTAL_DOMAIN": "portal.example.test", "PLATFORM_DOMAIN": "staff.example.test",
                   "COMPANY_NAME": "Deployment fixture", "COMPANY_CUI": "RO12345678", "COMPANY_COUNTRY_CODE": "RO",
                   "PYTHONPATH": str(ROOT / "services/platform"), "DJANGO_SETTINGS_MODULE": f"config.settings.{profile}"}
    result = subprocess.run([sys.executable, "-c",  # noqa: S603 -- fixed configuration inspection
                             "from django.conf import settings; import json; print(json.dumps([settings.IPWARE_TRUSTED_PROXY_LIST, settings.INTERNAL_SERVICE_ALLOWED_DOMAINS]))"],
                            cwd=ROOT / "services/platform", env=environment, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == [["127.0.0.1/32", "::1/128"], ["portal.example.test"]]
