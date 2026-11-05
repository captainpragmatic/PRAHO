"""Customer copy uses purchased allowances and separates billing from native fulfilment."""

from typing import Any


def financial_plan_change_block(locale: str) -> str:
    description = (
        "Schimbare de plan: {{target_plan_name}}. Spațiu alocat: {{disk_allowance}}; "
        "trafic alocat: {{bandwidth_allowance}}. Verificarea resurselor este separată de confirmarea plății."
        if locale == "ro"
        else "Plan change: {{target_plan_name}}. Assigned disk: {{disk_allowance}}; "
        "assigned bandwidth: {{bandwidth_allowance}}. Resource verification is separate from payment confirmation."
    )
    return "\n{% if is_plan_change %}<p>" + description + "</p>{% endif %}"


def operational_plan_change_templates() -> list[dict[str, Any]]:
    copy = {
        "ro": {
            "scheduled": ("Schimbarea planului este programată", "Planul va intra în vigoare la {{effective_date}}."),
            "completed": ("Resursele planului sunt verificate", "Limitele resurselor alocate au fost verificate."),
            "attention": (
                "Schimbarea planului necesită atenție",
                "Verificați starea în zona client sau contactați suportul.",
            ),
        },
        "en": {
            "scheduled": ("Your plan change is scheduled", "The plan takes effect at {{effective_date}}."),
            "completed": ("Your plan resources are verified", "The assigned resource limits have been verified."),
            "attention": (
                "Your plan change needs attention",
                "Check the status in your client area or contact support.",
            ),
        },
    }
    result: list[dict[str, Any]] = []
    for locale, phases in copy.items():
        for phase, (title, detail) in phases.items():
            terms = (
                "Spațiu alocat: {{disk_allowance}}. Trafic alocat: {{bandwidth_allowance}}. "
                "Tarif recurent total: {{next_recurring_total}} {{currency}}, TVA {{next_recurring_tax}} {{currency}}."
                if locale == "ro"
                else "Assigned disk: {{disk_allowance}}. Assigned bandwidth: {{bandwidth_allowance}}. "
                "Recurring total: {{next_recurring_total}} {{currency}}, VAT {{next_recurring_tax}} {{currency}}."
            )
            body = (
                "<p>{{customer_name}}</p><h2>"
                + title
                + "</h2><p>{{target_plan_name}}</p><p>"
                + detail
                + "</p><p>"
                + terms
                + "</p>"
            )
            result.append(
                {
                    "key": f"plan_change_{phase}",
                    "locale": locale,
                    "category": "service",
                    "subject": title + " - {{brand_name}}",
                    "body_html": body,
                    "description": "Hosting plan change phase; purchased terms only",
                }
            )
    return result
