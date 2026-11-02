"""Describe hosting dependencies truthfully without replacing customized notices."""

from importlib import import_module
from typing import Any

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor

INITIAL = import_module("apps.infrastructure.migrations.0008_node_maintenance_templates")
DESCRIPTION = "Customer node maintenance notices (hosting dependencies)"
CONTENT = {locale: dict(events) for locale, events in INITIAL.CONTENT.items()}
REPLACEMENTS = {
    "en": {
        "on the server your site runs on": "on a server supporting your hosting services",
        "Your site may be briefly unavailable.": "Some hosting functions may be briefly unavailable.",
        "The maintenance window for the server your site runs on has ended.": "The maintenance window affecting your hosting services has ended.",
    },
    "ro": {
        "pe serverul care găzduiește site-ul dumneavoastră": "pe un server care susține serviciile dumneavoastră de găzduire",
        "Site-ul poate fi indisponibil pentru scurt timp.": "Unele funcții de găzduire pot fi indisponibile pentru scurt timp.",
        "Intervalul de mentenanță pentru serverul care găzduiește site-ul dumneavoastră s-a încheiat.": "Intervalul de mentenanță pentru serviciile dumneavoastră de găzduire s-a încheiat.",
    },
}
for locale, events in CONTENT.items():
    for kind, (subject, text) in events.items():
        updated_text = text
        for original, neutral in REPLACEMENTS[locale].items():
            updated_text = updated_text.replace(original, neutral)
        events[kind] = (subject, updated_text)


def _values(subject: str, text: str, *, initial: bool) -> dict[str, Any]:
    return {
        "subject": subject,
        "body_text": text,
        "body_html": "<p>" + text.replace("\n\n", "</p><p>").replace("\n", "<br>") + "</p>",
        "category": "maintenance",
        "description": INITIAL.DESCRIPTION if initial else DESCRIPTION,
        "is_active": True,
        "version": 1 if initial else 2,
    }


def seed_neutral_templates(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    templates = apps.get_model("notifications", "EmailTemplate").objects.using(schema_editor.connection.alias)
    for locale, events in CONTENT.items():
        for kind, (subject, text) in events.items():
            initial = _values(*INITIAL.CONTENT[locale][kind], initial=True)
            neutral = _values(subject, text, initial=False)
            templates.filter(
                key=f"maintenance_{kind}", locale=locale, variables={}, created_by__isnull=True, **initial
            ).update(**neutral)
            templates.get_or_create(key=f"maintenance_{kind}", locale=locale, defaults=neutral)


def restore_initial_templates(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    templates = apps.get_model("notifications", "EmailTemplate").objects.using(schema_editor.connection.alias)
    for locale, events in CONTENT.items():
        for kind, (subject, text) in events.items():
            templates.filter(
                key=f"maintenance_{kind}",
                locale=locale,
                variables={},
                created_by__isnull=True,
                **_values(subject, text, initial=False),
            ).update(**_values(*INITIAL.CONTENT[locale][kind], initial=True))


class Migration(migrations.Migration):
    dependencies = [("infrastructure", "0011_merge_cloud_destroy_maintenance")]
    operations = [migrations.RunPython(seed_neutral_templates, restore_initial_templates)]
