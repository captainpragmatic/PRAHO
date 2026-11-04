"""One fixed release bundle for explicitly preparing imported-node inspection."""

import base64
import hashlib
import json
from typing import Any

from django.conf import settings

NATIVE_HELPERS = (
    "praho_quota.py",
    "praho_quota_native.py",
    "praho-quota-metadata.pl",
    "praho_usage.py",
    "praho_hosting_node.py",
    "praho-notification-policy.pl",
)


def helper_bundle() -> dict[str, Any]:
    root = settings.BASE_DIR / "infrastructure/ansible/playbooks/files"
    files = {name: base64.b64encode((root / name).read_bytes()).decode("ascii") for name in NATIVE_HELPERS}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"helper_bundle_digest": digest, "files": files}
