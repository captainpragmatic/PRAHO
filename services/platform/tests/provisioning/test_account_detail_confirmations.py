"""Rendered account confirmations and real HTMX fragments retain their locale."""

from __future__ import annotations

from collections.abc import Callable
from inspect import unwrap
from pathlib import Path
from typing import ClassVar, cast
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest, HttpResponse
from django.template import Context, Engine
from django.test import RequestFactory, SimpleTestCase
from django.urls import reverse
from django.utils import translation
from django.utils.html import escape

from apps.common.localisation import DisplayLocalisation
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_views import virtualmin_account_toggle_protection
from tests.ui.node_harness import Markup, dataset, run_node

ROOT = Path(__file__).resolve().parents[4]

HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const components = {};
const requests = [];
const events = [];
let swapped = null;
function escape(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}
const context = {
  console,
  document: {
    addEventListener(name, fn) { if (name === "alpine:init") fn(); },
    createElement() {
      return {textContent: "", get innerHTML() { return escape(this.textContent); }};
    }
  },
  window: {
    addEventListener() {},
    dispatchEvent(event) { events.push(event.detail); }
  },
  CustomEvent: function(name, options) { this.detail = options.detail; },
  Alpine: {data(name, factory) { components[name] = factory; }},
  htmx: {
    ajax(method, url, options) {
      requests.push({method, url, options});
      if (input.fragment && options.swap === "outerHTML") {
        // Apply the response at the transport boundary, including Alpine's new root.
        swapped = components.virtualminQuickActions();
        swapped.$root = {dataset: input.fragment};
        swapped.$dispatch = (name, detail) => events.push(detail);
      }
    }
  }
};
vm.runInNewContext(input.shared, context);
vm.runInNewContext(input.platform, context);
vm.runInNewContext(input.inline, context);
const modal = components.dangerousActionModal();
modal.$root = {dataset: input.defaults};
function confirm(detail) {
  modal.onConfirmRequest({detail});
  const result = {title: modal.title, message: modal.message, phrase: modal.confirmText};
  modal.userInput = "wrong";
  modal.submitIfValid();
  result.requestsBeforeConfirmation = requests.length;
  modal.userInput = modal.confirmText;
  modal.submitIfValid();
  result.closed = !modal.show;
  return result;
}
context[input.function]({dataset: input.button});
const initial = confirm(events.shift());
const afterSwap = [];
if (swapped) {
  swapped.confirmAccountDelete();
  afterSwap.push(confirm(events.shift()));
  swapped.confirmProtectionToggle();
  afterSwap.push(confirm(events.shift()));
}
process.stdout.write(JSON.stringify({initial, afterSwap, requests}));
"""


class AccountDetailConfirmationTests(SimpleTestCase):
    def render_account(self, *, protected: bool, domain: str = "hosting.example.com") -> str:
        engine = Engine(
            dirs=[str(ROOT / "services/platform/templates"), str(ROOT / "shared/ui/templates")],
            loaders=[
                (
                    "django.template.loaders.locmem.Loader",
                    {"base.html": ("{% block content %}{% endblock %}{% block extra_modals %}{% endblock %}")},
                ),
                "django.template.loaders.filesystem.Loader",
            ],
            libraries={
                "i18n": "django.templatetags.i18n",
                "ui_components": "apps.ui.templatetags.ui_components",
                "localisation_tags": "apps.ui.templatetags.localisation_tags",
            },
        )
        policy = DisplayLocalisation("ro", "RO", "Europe/Bucharest", "d.m.Y")
        with patch("apps.ui.templatetags.localisation_tags.get_request_localisation", return_value=policy):
            return engine.get_template("provisioning/virtualmin/account_detail.html").render(
                Context(
                    {
                        "account": {
                            "domain": domain,
                            "protected_from_deletion": protected,
                            "can_be_deleted": not protected,
                            "is_active": True,
                        },
                        "toggle_protection_url": "/protection/",
                        "delete_url": "/delete/",
                        "csrf_token": "test-token",
                    }
                )
            )

    def exercise(self, page: Markup, function: str, fragment: Markup | None = None) -> dict[str, object]:
        button = page.find("data-invoke", function + "Action")
        self.assertEqual(button["data-action"], "invoke")
        return run_node(
            HARNESS,
            {
                "shared": (ROOT / "shared/ui/static/js/alpine-shared-components.js").read_text(encoding="utf-8"),
                "platform": (ROOT / "services/platform/static/js/alpine-components.js").read_text(encoding="utf-8"),
                "inline": "\n".join(page.scripts),
                "defaults": dataset(page.find("x-data", "dangerousActionModal")),
                "button": dataset(button),
                "function": function,
                "fragment": dataset(fragment.find("id", "quick-actions-section")) if fragment else None,
            },
        )

    # Only deletion is irreversible; a protection toggle says which way it changes protection
    MESSAGES: ClassVar[dict[str, str]] = {
        "Disable Protection": "Deletion protection will be turned off for this account.",
        "Enable Protection": "Deletion protection will be turned on for this account.",
        "Delete Account": "This action cannot be undone.",
    }

    def confirmation(self, title: str, domain: str, requests_before: int) -> dict[str, object]:
        return {
            "title": translation.gettext(title),
            "message": str(escape(domain + ": " + translation.gettext(self.MESSAGES[title]))),
            "phrase": translation.gettext("I really am sure I want to do this!"),
            "requestsBeforeConfirmation": requests_before,
            "closed": True,
        }

    def test_account_confirmations_use_romanian_and_preserve_the_requested_action(self) -> None:
        with translation.override("ro"):
            cases = (
                ("confirmProtectionToggle", True, "Disable Protection", "POST", "/protection/"),
                ("confirmAccountDelete", False, "Delete Account", "DELETE", "/delete/"),
            )
            for function, protected, title, method, url in cases:
                with self.subTest(function=function):
                    page = Markup(self.render_account(protected=protected))
                    output = self.exercise(page, function)
                    self.assertEqual(output["initial"], self.confirmation(title, "hosting.example.com", 0))
                    options: dict[str, object] = {"target": "body"}
                    if protected:
                        options = {
                            "target": "#quick-actions-section",
                            "swap": "outerHTML",
                            "headers": {"X-CSRFToken": "test-token"},
                        }
                    self.assertEqual(output["requests"], [{"method": method, "url": url, "options": options}])

    def test_confirmations_use_the_translated_htmx_response_after_replacement(self) -> None:
        with translation.override("ro"):
            for domain in ("hosting.example.com", '<img src=x onerror="alert(1)">'):
                with self.subTest(domain=domain):
                    page = Markup(self.render_account(protected=True, domain=domain))
                    account = VirtualminAccount(
                        domain=domain, virtualmin_username="hosting", protected_from_deletion=True, status="active"
                    )
                    request = RequestFactory().post(
                        "/protection/",
                        HTTP_HX_REQUEST="true",
                        HTTP_HX_CURRENT_URL=f"/accounts/{account.pk}/",
                    )
                    request.user = AnonymousUser()
                    request.session = SessionStore()
                    request._messages = FallbackStorage(request)
                    view = cast(
                        "Callable[[HttpRequest, str], HttpResponse]", unwrap(virtualmin_account_toggle_protection)
                    )
                    with (
                        patch("apps.provisioning.virtualmin_views.get_object_or_404", return_value=account),
                        patch.object(VirtualminAccount, "save"),
                        patch("apps.common.context_processors._maintenance_mode_active", return_value=False),
                    ):
                        response = view(request, str(account.pk))
                    self.assertEqual(response.status_code, 200)
                    self.assertFalse(account.protected_from_deletion)
                    fragment = Markup(response.content.decode())
                    root = fragment.find("id", "quick-actions-section")
                    self.assertEqual(root["x-data"], "virtualminQuickActions()")
                    output = self.exercise(page, "confirmProtectionToggle", fragment)
                    self.assertEqual(
                        output["afterSwap"],
                        [
                            self.confirmation("Delete Account", domain, 1),
                            self.confirmation("Enable Protection", domain, 2),
                        ],
                    )
                    self.assertEqual(
                        output["requests"],
                        [
                            {
                                "method": "POST",
                                "url": "/protection/",
                                "options": {
                                    "target": "#quick-actions-section",
                                    "swap": "outerHTML",
                                    "headers": {"X-CSRFToken": "test-token"},
                                },
                            },
                            {
                                "method": "DELETE",
                                "url": reverse("provisioning:virtualmin_account_delete", args=[account.pk]),
                                "options": {"target": "body"},
                            },
                            {
                                "method": "POST",
                                "url": reverse("provisioning:virtualmin_account_toggle_protection", args=[account.pk]),
                                "options": {
                                    "target": "#quick-actions-section",
                                    "swap": "outerHTML",
                                    "headers": {"X-CSRFToken": root["data-csrf-token"]},
                                },
                            },
                        ],
                    )
