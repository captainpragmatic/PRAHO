"""Dev-only QA tool: full settings-catalog sweep against a running dev server.

Usage: .venv-darwin/bin/python scripts/qa_settings_sweep.py  (make dev running)

Full catalog sweep: every key changed via the real UI endpoints and restored.

Per key: original consumer-path read → mutate → POST /settings/save/ (or the
secret endpoints) with CSRF + baseline → consumer-path read shows new value →
audit event has actor/old/new/reason (+change-set id; masked when sensitive)
→ restore via a second real save → consumer-path read shows original again.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

import django
import requests

_PLATFORM = Path(__file__).resolve().parent.parent / "services" / "platform"
sys.path.insert(0, str(_PLATFORM))
os.chdir(_PLATFORM)
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings.dev"
django.setup()

from django.contrib.contenttypes.models import ContentType

from apps.audit.models import AuditEvent
from apps.billing.efactura.settings import efactura_settings
from apps.common.encryption import is_encrypted
from apps.settings.catalog import CATALOG
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

BASE = "http://localhost:8700"
REASON = "QA sweep 226"
SETTING_CT = ContentType.objects.get_for_model(SystemSetting)

import re as _re

session = requests.Session()


def _page_token(path: str) -> str:
    html = session.get(f"{BASE}{path}").text
    match = _re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


session.post(
    f"{BASE}/auth/login/",
    data={
        "email": "admin@pragmatichost.com",
        "password": "admin123",
        "csrfmiddlewaretoken": _page_token("/auth/login/"),
    },
    headers={"Referer": f"{BASE}/auth/login/"},
)
assert session.get(f"{BASE}/settings/").status_code == 200, "login failed"
CSRF_TOKEN = session.cookies.get("csrftoken") or _page_token("/settings/billing/")


def csrf_headers() -> dict:
    token = session.cookies.get("csrftoken") or CSRF_TOKEN
    return {"X-CSRFToken": token, "Content-Type": "application/json", "Referer": BASE}


def consumer_read(key: str):
    """Read at the consumer boundary with a cold local cache (DB truth)."""
    SettingsService._clear_setting_cache(key)
    if key.startswith("efactura."):
        return efactura_settings._get_setting(key, None)
    return SettingsService.get_setting(key)


def normalize(definition, value):
    if definition.data_type == "decimal" and value is not None:
        return Decimal(str(value))
    return value


def mutate(definition, original):
    rules = definition.validation or {}
    choices = rules.get("choices")
    if choices:
        idx = choices.index(original) if original in choices else -1
        return choices[(idx + 1) % len(choices)]
    if definition.data_type == "boolean":
        return not bool(original)
    if definition.data_type == "integer":
        original = int(original or 0)
        candidate = original + 1
        maximum = rules.get("max")
        minimum = rules.get("min")
        if maximum is not None and candidate > maximum:
            candidate = original - 1
        if minimum is not None and candidate < minimum:
            candidate = minimum + 1
        return candidate if candidate != original else original + 2
    if definition.data_type == "decimal":
        return str(Decimal(str(original or "0")) + 1)
    if definition.data_type == "list":
        base = list(original or [])
        probe = "qa-sweep" if all(isinstance(item, str) for item in base) else 99
        return [*base, probe]
    if definition.data_type == "json":
        data = copy.deepcopy(original or {})
        for k, v in data.items():
            if isinstance(v, int):
                data[k] = v + 1
                return data
        data["_qa_sweep"] = 1
        return data
    # string
    return f"{original}-qa" if original else "qa-sweep-value"


def get_baseline(key: str) -> str | None:
    response = session.get(f"{BASE}/settings/api/{key}/")
    if response.status_code != 200:
        return None
    return response.json()["setting"].get("updated_at")


def save(key: str, value, baseline):
    return session.post(
        f"{BASE}/settings/save/",
        data=json.dumps({"changes": {key: value}, "baselines": {key: baseline}, "reason": REASON}, default=str),
        headers=csrf_headers(),
    )


def latest_audit(key: str):
    return AuditEvent.objects.filter(content_type=SETTING_CT, metadata__setting_key=key).order_by("-timestamp").first()


def audit_ok(key: str, sensitive: bool) -> str | None:
    event = latest_audit(key)
    if event is None:
        return "no audit event"
    if event.user is None or event.user.email != "admin@pragmatichost.com":
        return f"actor={getattr(event.user, 'email', None)}"
    if not event.new_values.get("value"):
        return "no new value"
    if event.action == "update" and "value" not in event.old_values:
        return "no old value"
    if sensitive:
        if "(hidden)" not in str(event.new_values.get("value")):
            return "SENSITIVE NEW VALUE VISIBLE"
        if event.old_values.get("value") is not None and "(hidden)" not in str(event.old_values.get("value")):
            return "SENSITIVE OLD VALUE VISIBLE"
    else:
        if not event.metadata.get("change_set_id"):
            return "no change_set_id"
        if event.metadata.get("reason") != REASON:
            return f"reason={event.metadata.get('reason')}"
    return None


def sweep_regular(definition) -> list[str]:
    key = definition.key
    problems: list[str] = []
    original = consumer_read(key)
    new_value = mutate(definition, original)

    response = save(key, new_value, get_baseline(key))
    if response.status_code != 200:
        return [f"save {response.status_code}: {response.text[:120]}"]
    returned = response.json()["saved"][key]

    seen = consumer_read(key)
    if normalize(definition, seen) != normalize(definition, new_value):
        problems.append(f"consumer saw {seen!r} expected {new_value!r}")
    issue = audit_ok(key, sensitive=False)
    if issue:
        problems.append(f"audit: {issue}")

    # server-rendered display check for simple scalars
    if definition.input_kind in ("number", "text"):
        page = session.get(f"{BASE}/settings/{definition.group}/").text
        anchor = page.find(f'data-key="{key}"')
        if anchor == -1 or f'value="{new_value}"' not in page[anchor - 600 : anchor + 600]:
            problems.append("rendered page missing new value")

    restore = save(key, original, returned["baseline"])
    if restore.status_code != 200:
        problems.append(f"restore {restore.status_code}: {restore.text[:120]}")
    else:
        back = consumer_read(key)
        if normalize(definition, back) != normalize(definition, original):
            problems.append(f"restore mismatch: {back!r} != {original!r}")
    return problems


def sweep_secret(definition) -> list[str]:
    key = definition.key
    problems: list[str] = []
    original = consumer_read(key)
    probe = f"qa-sweep-secret-{abs(hash(key)) % 10_000}"

    response = session.post(
        f"{BASE}/settings/secret/{key}/", data=json.dumps({"value": probe, "reason": REASON}), headers=csrf_headers()
    )
    if response.status_code != 200:
        return [f"secret set {response.status_code}: {response.text[:120]}"]

    if consumer_read(key) != probe:
        problems.append("consumer did not see new secret")
    row = SystemSetting.objects.get(key=key)
    if not is_encrypted(str(row.value)):
        problems.append("stored secret NOT encrypted")
    if probe in str(row.value):
        problems.append("plaintext stored")
    issue = audit_ok(key, sensitive=True)
    if issue:
        problems.append(f"audit: {issue}")
    page = session.get(f"{BASE}/settings/{definition.group}/").text
    if probe in page:
        problems.append("secret rendered on page")

    if original:
        restore = session.post(
            f"{BASE}/settings/secret/{key}/",
            data=json.dumps({"value": original, "reason": "QA sweep restore"}),
            headers=csrf_headers(),
        )
    else:
        restore = session.post(
            f"{BASE}/settings/secret/{key}/clear/",
            data=json.dumps({"reason": "QA sweep restore"}),
            headers=csrf_headers(),
        )
    if restore.status_code != 200:
        problems.append(f"secret restore {restore.status_code}")
    elif (consumer_read(key) or "") != (original or ""):
        problems.append("secret restore mismatch")
    return problems


results = {}
for definition in CATALOG:
    try:
        problems = sweep_secret(definition) if definition.sensitive else sweep_regular(definition)
    except Exception as error:
        problems = [f"exception: {error}"]
    results[definition.key] = problems
    if problems:
        print(f"FAIL {definition.key}: {problems}")

passed = sum(1 for problems in results.values() if not problems)
print(f"\n{passed}/{len(results)} keys passed the full change→verify→audit→restore cycle")
report_path = Path("/tmp") / "settings_sweep_results.json"  # noqa: S108  # dev-only report
with report_path.open("w") as fh:
    json.dump(results, fh, indent=1, default=str)
print(f"report: {report_path}")
