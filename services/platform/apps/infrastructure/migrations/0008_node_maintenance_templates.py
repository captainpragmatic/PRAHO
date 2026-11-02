"""Install editable, localized notices without replacing an operator's existing templates."""

from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor

DESCRIPTION = "Customer node maintenance notices (initial defaults)"
CONTENT = {
    "en": {
        "scheduled": (
            "{% if is_emergency %}Emergency maintenance for your hosting{% else %}Scheduled maintenance for your hosting{% endif %}",
            "{% if is_emergency %}Emergency work is underway on the server your site runs on.{% else %}Maintenance is scheduled on the server your site runs on.{% endif %}\n\n"
            "Window: {{ display_starts_at }} - {{ display_ends_at }} ({{ display_timezone }}).\n\n"
            "{% if expects_downtime %}Your site may be briefly unavailable.{% if expected_downtime_minutes %} Expected interruption: up to {{ expected_downtime_minutes }} minutes.{% endif %}{% else %}No downtime is expected.{% endif %}\n\n"
            "{{ customer_note }}\n\nSign in to your customer portal for current status.",
        ),
        "completed": (
            "Maintenance outcome for your hosting",
            "The maintenance window for the server your site runs on has ended.\n\n"
            "{{ public_outcome }}\n\n{% if completion_source == 'operator' %}An operator recorded this outcome.{% else %}The maintenance job recorded this outcome.{% endif %}\n\n"
            "Sign in to your customer portal for current status.",
        ),
        "correction": (
            "Your hosting maintenance announcement has changed",
            "{% if withdrawal %}An earlier maintenance announcement no longer applies to your account.{% elif status == 'cancelled' %}The previously announced maintenance has been cancelled.{% else %}The previously announced maintenance window has changed.\n\n"
            "New window: {{ display_starts_at }} - {{ display_ends_at }} ({{ display_timezone }}).\n\n{{ customer_note }}{% endif %}\n\n"
            "Sign in to your customer portal for current status.",
        ),
    },
    "ro": {
        "scheduled": (
            "{% if is_emergency %}Mentenanță de urgență pentru găzduirea dumneavoastră{% else %}Mentenanță programată pentru găzduirea dumneavoastră{% endif %}",
            "{% if is_emergency %}Sunt în desfășurare lucrări urgente pe serverul care găzduiește site-ul dumneavoastră.{% else %}Sunt programate lucrări pe serverul care găzduiește site-ul dumneavoastră.{% endif %}\n\n"
            "Interval: {{ display_starts_at }} - {{ display_ends_at }} ({{ display_timezone }}).\n\n"
            "{% if expects_downtime %}Site-ul poate fi indisponibil pentru scurt timp.{% if expected_downtime_minutes %} Întrerupere estimată: până la {{ expected_downtime_minutes }} minute.{% endif %}{% else %}Nu sunt așteptate întreruperi.{% endif %}\n\n"
            "{{ customer_note }}\n\nPentru starea actuală, autentificați-vă în portalul pentru clienți.",
        ),
        "completed": (
            "Rezultatul mentenanței pentru găzduirea dumneavoastră",
            "Intervalul de mentenanță pentru serverul care găzduiește site-ul dumneavoastră s-a încheiat.\n\n"
            "{{ public_outcome }}\n\n{% if completion_source == 'operator' %}Un operator a înregistrat acest rezultat.{% else %}Procesul de mentenanță a înregistrat acest rezultat.{% endif %}\n\n"
            "Pentru starea actuală, autentificați-vă în portalul pentru clienți.",
        ),
        "correction": (
            "Anunțul de mentenanță pentru găzduire s-a modificat",
            "{% if withdrawal %}Un anunț anterior de mentenanță nu se mai aplică contului dumneavoastră.{% elif status == 'cancelled' %}Mentenanța anunțată anterior a fost anulată.{% else %}Intervalul de mentenanță anunțat anterior s-a modificat.\n\n"
            "Noul interval: {{ display_starts_at }} - {{ display_ends_at }} ({{ display_timezone }}).\n\n{{ customer_note }}{% endif %}\n\n"
            "Pentru starea actuală, autentificați-vă în portalul pentru clienți.",
        ),
    },
}


def seed_templates(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    templates = apps.get_model("notifications", "EmailTemplate").objects.using(schema_editor.connection.alias)
    for locale, events in CONTENT.items():
        for kind, (subject, text) in events.items():
            templates.get_or_create(
                key=f"maintenance_{kind}", locale=locale,
                defaults={"subject": subject, "body_text": text,
                          "body_html": "<p>" + text.replace("\n\n", "</p><p>").replace("\n", "<br>") + "</p>",
                          "category": "maintenance", "description": DESCRIPTION, "is_active": True, "version": 1},
            )


def remove_unchanged_templates(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    templates = apps.get_model("notifications", "EmailTemplate").objects.using(schema_editor.connection.alias)
    for locale, events in CONTENT.items():
        for kind, (subject, text) in events.items():
            templates.filter(
                key=f"maintenance_{kind}", locale=locale, subject=subject, body_text=text,
                body_html="<p>" + text.replace("\n\n", "</p><p>").replace("\n", "<br>") + "</p>",
                category="maintenance", description=DESCRIPTION, version=1,
            ).delete()


class Migration(migrations.Migration):
    dependencies = [("infrastructure", "0007_node_maintenance"), ("notifications", "0012_email_suppression_opt_out")]
    operations = [migrations.RunPython(seed_templates, remove_unchanged_templates)]
