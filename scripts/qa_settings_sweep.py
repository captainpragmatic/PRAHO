"""Dev-only QA tool: full settings-catalog sweep against a running dev server.

Usage: .venv-darwin/bin/python scripts/qa_settings_sweep.py  (make dev running)

Scope of proof per key: authenticated write through the real save/secret
endpoints (in the widget wire encoding) -> database persistence -> delivery at
the consumer-boundary getter -> write-anchored audit event matched to the
response change-set id with exact old/new display values -> restore inside a
finally with an ORM fallback. One multi-key atomic change set and one
server-process cache-invalidation canary (maintenance banner) run per sweep.
NOT covered here: the browser widget layer (Playwright suite), deep consumer
business behavior (integration suite), CSRF enforcement (disabled in dev;
covered by unit tests).

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


def wire_encode(definition, value):
    """Encode exactly as the browser widgets do (_form_js.html compute())."""
    if definition.data_type in ("integer", "decimal"):
        return str(value)  # number inputs submit el.value strings
    if definition.data_type == "json":
        return json.dumps(value)  # the JSON textarea submits its raw string
    return value  # bool stays bool, list stays array, strings stay strings


def save(key: str, value, baseline):
    return session.post(
        f"{BASE}/settings/save/",
        data=json.dumps({"changes": {key: value}, "baselines": {key: baseline}, "reason": REASON}, default=str),
        headers=csrf_headers(),
    )


def audit_anchor() -> float:
    latest = AuditEvent.objects.filter(content_type=SETTING_CT).order_by("-timestamp").first()
    return latest.timestamp.timestamp() if latest else 0.0


def audit_ok(  # noqa: PLR0913  # One return per distinct audit defect
    key: str,
    sensitive: bool,
    anchor: float,
    expected_old: str | None = None,
    expected_new: str | None = None,
    change_set_id: str | None = None,
    reason: str = REASON,
) -> str | None:
    event = AuditEvent.objects.filter(content_type=SETTING_CT, metadata__setting_key=key).order_by("-timestamp").first()
    if event is None:
        return "no audit event"
    if event.timestamp.timestamp() <= anchor:
        return "no NEW audit event since write (a stale event would have passed)"
    if event.user is None or event.user.email != "admin@pragmatichost.com":
        return f"actor={getattr(event.user, 'email', None)}"
    if event.metadata.get("reason") != reason:
        return f"reason={event.metadata.get('reason')}"
    if sensitive:
        if "(hidden)" not in str(event.new_values.get("value")):
            return "SENSITIVE NEW VALUE VISIBLE"
        if event.old_values.get("value") is not None and "(hidden)" not in str(event.old_values.get("value")):
            return "SENSITIVE OLD VALUE VISIBLE"
        return None
    if change_set_id and event.metadata.get("change_set_id") != change_set_id:
        return f"change_set_id mismatch: {event.metadata.get('change_set_id')} != {change_set_id}"
    if expected_new is not None and str(event.new_values.get("value")) != expected_new:
        return f"new_values {event.new_values.get('value')!r} != expected {expected_new!r}"
    if expected_old is not None and str(event.old_values.get("value")) != expected_old:
        return f"old_values {event.old_values.get('value')!r} != expected {expected_old!r}"
    return None


def row_display(key: str) -> str | None:
    row = SystemSetting.objects.filter(key=key).first()
    return str(row.get_display_value()) if row else None


def force_restore(key: str, original) -> None:
    """ORM fallback so no failure path can leave the system mutated."""
    result = SettingsService.update_setting(key, original, reason="QA sweep emergency restore")
    if not result.is_ok():
        print(f"EMERGENCY RESTORE FAILED for {key}: {result.error}")


def sweep_regular(definition) -> list[str]:
    key = definition.key
    problems: list[str] = []
    original = consumer_read(key)
    old_display = row_display(key)
    new_value = mutate(definition, original)
    anchor = audit_anchor()
    mutated = False
    returned = None
    try:
        response = save(key, wire_encode(definition, new_value), get_baseline(key))
        if response.status_code != 200:
            return [f"save {response.status_code}: {response.text[:120]}"]
        mutated = True
        body = response.json()
        returned = body["saved"][key]
        change_set_id = body["change_set_id"]

        seen = consumer_read(key)
        if normalize(definition, seen) != normalize(definition, new_value):
            problems.append(f"consumer saw {seen!r} expected {new_value!r}")
        issue = audit_ok(
            key,
            sensitive=False,
            anchor=anchor,
            expected_old=old_display,
            expected_new=row_display(key),
            change_set_id=change_set_id,
        )
        if issue:
            problems.append(f"audit: {issue}")

        # server-rendered display check for simple scalars
        if definition.input_kind in ("number", "text"):
            page = session.get(f"{BASE}/settings/{definition.group}/").text
            marker = page.find(f'data-key="{key}"')
            if marker == -1 or f'value="{new_value}"' not in page[marker - 600 : marker + 600]:
                problems.append("rendered page missing new value")
    finally:
        if mutated:
            restore_anchor = audit_anchor()
            restore = save(key, wire_encode(definition, original), returned["baseline"] if returned else None)
            if restore.status_code != 200:
                problems.append(f"restore {restore.status_code}: {restore.text[:120]}")
                force_restore(key, original)
            else:
                back = consumer_read(key)
                if normalize(definition, back) != normalize(definition, original):
                    problems.append(f"restore mismatch: {back!r} != {original!r}")
                    force_restore(key, original)
                restore_issue = audit_ok(key, sensitive=False, anchor=restore_anchor)
                if restore_issue:
                    problems.append(f"restore audit: {restore_issue}")
    return problems


def sweep_secret(definition) -> list[str]:
    key = definition.key
    problems: list[str] = []
    original = consumer_read(key)
    probe = f"qa-sweep-secret-{abs(hash(key)) % 10_000}"
    anchor = audit_anchor()
    mutated = False
    try:
        response = session.post(
            f"{BASE}/settings/secret/{key}/",
            data=json.dumps({"value": probe, "reason": REASON}),
            headers=csrf_headers(),
        )
        if response.status_code != 200:
            return [f"secret set {response.status_code}: {response.text[:120]}"]
        mutated = True

        if consumer_read(key) != probe:
            problems.append("consumer did not see new secret")
        row = SystemSetting.objects.get(key=key)
        if not is_encrypted(str(row.value)):
            problems.append("stored secret NOT encrypted")
        if probe in str(row.value):
            problems.append("plaintext stored")
        issue = audit_ok(key, sensitive=True, anchor=anchor)
        if issue:
            problems.append(f"audit: {issue}")
        page = session.get(f"{BASE}/settings/{definition.group}/").text
        if probe in page:
            problems.append("secret rendered on page")
    finally:
        if mutated:
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
                force_restore(key, original or "")
            elif (consumer_read(key) or "") != (original or ""):
                problems.append("secret restore mismatch")
                force_restore(key, original or "")
    return problems


def server_cache_invalidation_canary() -> list[str]:
    """Prove the SERVER process re-reads a changed value through its own cache:
    the settings home banner renders via the server's get_boolean_setting."""
    problems: list[str] = []
    banner = "Maintenance mode is active"
    if banner in session.get(f"{BASE}/settings/").text:
        return ["canary precondition: banner already active"]
    response = save("system.maintenance_mode", True, get_baseline("system.maintenance_mode"))
    if response.status_code != 200:
        return [f"canary save {response.status_code}"]
    try:
        if banner not in session.get(f"{BASE}/settings/").text:
            problems.append("server did not see maintenance ON through its own cache")
    finally:
        returned = response.json()["saved"]["system.maintenance_mode"]
        off = save("system.maintenance_mode", False, returned["baseline"])
        if off.status_code != 200:
            problems.append(f"canary restore {off.status_code}")
            force_restore("system.maintenance_mode", False)
        elif banner in session.get(f"{BASE}/settings/").text:
            problems.append("server still shows maintenance after OFF")
    return problems


def multi_key_change_set() -> list[str]:
    """One real multi-dirty atomic change set through HTTP."""
    keys = ["billing.invoice_payment_terms_days", "billing.proforma_validity_days", "domains.expiry_warning_days"]
    originals = {k: consumer_read(k) for k in keys}
    baselines = {k: get_baseline(k) for k in keys}
    changes = {k: int(originals[k]) + 1 for k in keys}
    response = session.post(
        f"{BASE}/settings/save/",
        data=json.dumps({"changes": changes, "baselines": baselines, "reason": REASON}),
        headers=csrf_headers(),
    )
    if response.status_code != 200:
        return [f"multi save {response.status_code}: {response.text[:120]}"]
    body = response.json()
    problems = []
    ids = set()
    for k in keys:
        if consumer_read(k) != changes[k]:
            problems.append(f"{k} not applied")
        event = (
            AuditEvent.objects.filter(content_type=SETTING_CT, metadata__setting_key=k).order_by("-timestamp").first()
        )
        ids.add(event.metadata.get("change_set_id") if event else None)
    if ids != {body["change_set_id"]}:
        problems.append(f"change-set ids not shared: {ids}")
    restore = session.post(
        f"{BASE}/settings/save/",
        data=json.dumps(
            {
                "changes": {k: originals[k] for k in keys},
                "baselines": {k: body["saved"][k]["baseline"] for k in keys},
                "reason": "QA sweep restore",
            },
            default=str,
        ),
        headers=csrf_headers(),
    )
    if restore.status_code != 200:
        problems.append(f"multi restore {restore.status_code}")
        for k in keys:
            force_restore(k, originals[k])
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

results["__multi_key_change_set__"] = multi_key_change_set()
results["__server_cache_canary__"] = server_cache_invalidation_canary()
for special in ("__multi_key_change_set__", "__server_cache_canary__"):
    if results[special]:
        print(f"FAIL {special}: {results[special]}")

key_results = {k: v for k, v in results.items() if not k.startswith("__")}
if len(key_results) != len(CATALOG):
    print(f"COUNT MISMATCH: swept {len(key_results)} of {len(CATALOG)} catalog keys")
    results["__count__"] = ["mismatch"]
passed = sum(1 for problems in key_results.values() if not problems)
print(f"\n{passed}/{len(CATALOG)} keys passed the full change→verify→audit→restore cycle")
report_path = Path("/tmp") / "settings_sweep_results.json"  # noqa: S108  # dev-only report
with report_path.open("w") as fh:
    json.dump(results, fh, indent=1, default=str)
print(f"report: {report_path}")
if any(problems for problems in results.values()):
    sys.exit(1)
