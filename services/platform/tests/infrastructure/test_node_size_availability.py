"""A node size is offered only in the regions where its provider still sells it."""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse

from apps.common.types import Ok
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from tests.helpers.node_catalogue import make_region, make_size

User = get_user_model()


class SizeCreateTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="admin@test.com", password="testpass123"))
        self.hetzner = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.other = CloudProvider.objects.create(name="Vultr", provider_type="vultr", code="vul")

    def test_new_size_is_offered_in_every_active_region_of_its_provider(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        fsn1 = make_region(self.hetzner, "fsn1")
        make_region(self.hetzner, "nbg1", active=False)
        make_region(self.other, "ewr")
        response = self.client.post(
            reverse("infrastructure:size_create"),
            {
                "provider": self.hetzner.pk, "name": "CX23", "display_name": "2 vCPU / 4GB / 40GB",
                "provider_type_id": "cx23", "vcpus": 2, "memory_gb": 4, "disk_gb": 40,
                "hourly_cost_eur": "0.0100", "monthly_cost_eur": "4.99", "max_domains": 50,
                "max_bandwidth_gb": 1000, "is_active": True, "sort_order": 2,
            },
        )
        self.assertEqual(response.status_code, 302)
        size = NodeSize.objects.get(provider_type_id="cx23")
        self.assertEqual(set(size.available_regions.all()), {hel1, fsn1})


def _setting(key: str, default: object = None) -> object:
    return "nodes.example.com" if key == "node_deployment.dns_default_zone" else default


@patch("apps.infrastructure.views.SettingsService.get_setting", side_effect=_setting)
@patch("apps.infrastructure.views.deployment_configuration_issues", return_value=[])
class DeploymentCreateSizeRegionTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="admin@test.com", password="testpass123"))
        self.provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.hel1 = make_region(self.provider, "hel1")
        self.ash = make_region(self.provider, "ash")
        self.cpx11 = make_size(self.provider, "cpx11", self.ash)
        self.cx23 = make_size(self.provider, "cx23", self.hel1)
        self.panel = PanelType.objects.create(name="Virtualmin", panel_type="virtualmin", ansible_playbook="v.yml")

    def post(self, region: NodeRegion, size: NodeSize) -> HttpResponse:
        with (
            patch("apps.infrastructure.views.get_provider_token", return_value=Ok("fixture-token")),
            patch("apps.infrastructure.views.queue_deploy_node", return_value="task-1"),
        ):
            return self.client.post(
                reverse("infrastructure:deployment_create"),
                {
                    "environment": "stg", "node_type": "sha", "provider": self.provider.pk, "region": region.pk,
                    "node_size": size.pk, "panel_type": self.panel.pk, "backup_enabled": True,
                },
            )

    def test_size_not_sold_in_region_is_refused(self, *_mocks: MagicMock) -> None:
        response = self.post(self.hel1, self.cpx11)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(NodeDeployment.objects.exists())
        self.assertIn("node_size", response.context["form"].errors)

    def test_size_sold_in_region_is_accepted(self, *_mocks: MagicMock) -> None:
        response = self.post(self.hel1, self.cx23)
        self.assertEqual(response.status_code, 302)
        deployment = NodeDeployment.objects.get()
        self.assertEqual((deployment.region, deployment.node_size), (self.hel1, self.cx23))

    def test_page_lists_the_regions_each_size_is_offered_in(self, *_mocks: MagicMock) -> None:
        make_region(self.provider, "fsn1").available_sizes.add(self.cx23)
        response = self.client.get(reverse("infrastructure:deployment_create"))
        self.assertEqual(response.status_code, 200)
        sizes = {entry["name"]: entry for entry in response.context["sizes_data"]}
        self.assertEqual(sorted(sizes), ["CPX11", "CX23"])  # One entry per size, however many regions.
        self.assertEqual(sizes["CPX11"].get("region_ids"), [self.ash.pk])
        fsn1 = NodeRegion.objects.get(provider_region_id="fsn1")
        self.assertEqual(sorted(sizes["CX23"].get("region_ids") or []), sorted([self.hel1.pk, fsn1.pk]))


class DeployNodeCommandSizeRegionTests(TestCase):
    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.hel1 = make_region(self.provider, "hel1")
        make_size(self.provider, "cpx11", make_region(self.provider, "ash"))
        make_size(self.provider, "cx23", self.hel1)
        PanelType.objects.create(name="Virtualmin", panel_type="virtualmin", ansible_playbook="v.yml")

    def call(self, size: str) -> str:
        out = StringIO()
        with (
            patch("apps.settings.services.SettingsService.get_setting", side_effect=_setting),
            patch(
                "apps.infrastructure.management.commands.deploy_node.get_provider_token",
                return_value=Ok("fixture-token"),
            ),
        ):
            call_command(
                "deploy_node", "--provider=hetzner", "--environment=stg", "--region=hel1", f"--size={size}",
                "--dry-run", stdout=out,
            )
        return out.getvalue()

    def test_size_not_sold_in_region_is_refused(self) -> None:
        with self.assertRaisesMessage(CommandError, "Size 'cpx11' is not available in hel1. Available there: cx23"):
            self.call("cpx11")

    def test_size_sold_in_region_is_planned(self) -> None:
        self.assertIn("DRY RUN", self.call("cx23"))
