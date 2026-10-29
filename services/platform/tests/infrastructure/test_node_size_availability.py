"""A node size is offered only in the regions where its provider still sells it."""

from __future__ import annotations

from io import StringIO
from typing import Any
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


class SizeFormTests(TestCase):
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

    def edit(self, size: NodeSize, **changes: object) -> None:
        data = {
            "provider": size.provider_id, "name": size.name, "display_name": size.display_name,
            "provider_type_id": size.provider_type_id, "vcpus": size.vcpus, "memory_gb": size.memory_gb,
            "disk_gb": size.disk_gb, "hourly_cost_eur": size.hourly_cost_eur, "monthly_cost_eur": size.monthly_cost_eur,
            "max_domains": size.max_domains, "max_bandwidth_gb": size.max_bandwidth_gb, "is_active": size.is_active,
            "sort_order": size.sort_order,
        }
        data.update(changes)
        response = self.client.post(reverse("infrastructure:size_edit", args=[size.pk]), data)
        self.assertEqual(response.status_code, 302)

    def test_changing_the_provider_type_offers_the_size_where_the_new_type_may_be_sold(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        ash = make_region(self.hetzner, "ash")
        size = make_size(self.hetzner, "cx23", hel1)
        self.edit(size, provider_type_id="cpx11")
        self.assertEqual(set(size.available_regions.all()), {hel1, ash})

    def test_changing_the_provider_moves_the_offer_to_the_new_provider(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        ewr = make_region(self.other, "ewr")
        size = make_size(self.hetzner, "cx23", hel1)
        self.edit(size, provider=self.other.pk)
        self.assertEqual(set(size.available_regions.all()), {ewr})

    def test_editing_other_fields_keeps_the_synced_offer(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        make_region(self.hetzner, "ash")
        size = make_size(self.hetzner, "cx23", hel1)
        self.edit(size, display_name="2 vCPU / 4 GB")
        self.assertEqual(set(size.available_regions.all()), {hel1})


class RegionToggleTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="admin@test.com", password="testpass123"))
        self.hetzner = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")

    def toggle(self, region: NodeRegion) -> None:
        self.client.post(reverse("infrastructure:region_toggle", args=[region.pk]))
        region.refresh_from_db()

    def test_enabling_a_region_nothing_is_offered_in_offers_the_active_sizes(self) -> None:
        hel1 = make_region(self.hetzner, "hel1")
        sin = make_region(self.hetzner, "sin", active=False)  # Disabled before the catalogue recorded regions.
        cx23 = make_size(self.hetzner, "cx23", hel1)
        make_size(self.hetzner, "cx11", hel1, active=False)
        other = CloudProvider.objects.create(name="Vultr", provider_type="vultr", code="vul")
        make_size(other, "vc2", make_region(other, "ewr"))
        self.toggle(sin)
        self.assertTrue(sin.is_active)
        self.assertEqual(set(sin.available_sizes.all()), {cx23})

    def test_enabling_a_region_keeps_its_synced_offer(self) -> None:
        hel1 = make_region(self.hetzner, "hel1", active=False)
        cx23 = make_size(self.hetzner, "cx23", hel1)
        make_size(self.hetzner, "cpx11", make_region(self.hetzner, "ash"))
        self.toggle(hel1)
        self.assertEqual(set(hel1.available_sizes.all()), {cx23})


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


class UpgradeSizeRegionTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="admin@test.com", password="testpass123"))
        provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.hel1 = make_region(provider, "hel1")
        current = make_size(provider, "cx23", self.hel1)
        self.cpx22 = make_size(provider, "cpx22", self.hel1)
        self.cpx31 = make_size(provider, "cpx31", make_region(provider, "ash"))  # Not sold in hel1.
        self.ccx13 = make_size(provider, "ccx13", self.hel1, active=False)  # Withdrawn by the last sync.
        panel = PanelType.objects.create(name="Virtualmin", panel_type="virtualmin", ansible_playbook="v.yml")
        self.deployment = NodeDeployment.objects.create(
            environment="stg", node_type="sha", provider=provider, region=self.hel1, node_size=current,
            panel_type=panel, hostname="stg-sha-het-fi-hel1-001", node_number=1, status="completed",
            external_node_id="4242",
        )

    def upgrade(self, size: NodeSize) -> tuple[Any, MagicMock]:
        from apps.infrastructure.deployment_service import NodeDeploymentService  # noqa: PLC0415  # Test-local

        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            service = NodeDeploymentService()
        with patch("apps.infrastructure.deployment_service.run_provider_command") as resize:
            result = service.upgrade_node_size(self.deployment, size, {"api_token": "fixture-token"})
        return result, resize

    def test_resize_to_a_size_not_sold_in_the_region_is_refused(self) -> None:
        for size in (self.cpx31, self.ccx13):
            with self.subTest(size=size.provider_type_id):
                result, resize = self.upgrade(size)
                self.assertTrue(result.is_err())
                self.assertIn("not available in hel1", result.unwrap_err())
                resize.assert_not_called()

    def test_upgrade_page_lists_and_accepts_only_sizes_sold_in_the_region(self) -> None:
        url = reverse("infrastructure:deployment_upgrade", args=[self.deployment.pk])
        listed = self.client.get(url).context["available_sizes"]
        self.assertEqual([size.provider_type_id for size in listed], ["cpx22"])
        with (
            patch("apps.infrastructure.views.get_provider_token", return_value=Ok("fixture-token")),
            patch("apps.infrastructure.views.queue_upgrade_node", return_value="task-1") as queue,
        ):
            self.client.post(url, {"new_size": self.cpx31.pk})
            self.client.post(url, {"new_size": self.ccx13.pk})
            queue.assert_not_called()
            self.client.post(url, {"new_size": self.cpx22.pk})
            queue.assert_called_once()
