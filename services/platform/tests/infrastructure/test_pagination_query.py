"""Regression tests for deployment list pagination."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from urllib.parse import urljoin

from django.core.paginator import Page
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, next_page_url


class DeploymentPaginationQueryTests(TestCase):
    def test_next_page_preserves_filters_and_matching_deployments(self) -> None:
        staff = User.objects.create_user(email="deployment-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        providers = CloudProvider.objects.bulk_create(
            [
                CloudProvider(name="Paging Hetzner", provider_type="hetzner", code="het"),
                CloudProvider(name="Paging Vultr", provider_type="vultr", code="vul"),
            ]
        )
        regions = NodeRegion.objects.bulk_create(
            [
                NodeRegion(
                    provider=provider,
                    name="Paging Region",
                    provider_region_id="fsn1",
                    normalized_code="fsn1",
                    country_code="de",
                )
                for provider in providers
            ]
        )
        sizes = NodeSize.objects.bulk_create(
            [
                NodeSize(
                    provider=provider,
                    name="Small",
                    display_name="Small",
                    provider_type_id="small",
                    vcpus=2,
                    memory_gb=4,
                    disk_gb=40,
                    hourly_cost_eur=Decimal("0.01"),
                    monthly_cost_eur=Decimal("7.20"),
                )
                for provider in providers
            ]
        )
        panel = PanelType.objects.create(
            name="Paging Panel", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )

        def deployment(
            number: int,
            *,
            environment: str = "prd",
            node_type: str = "sha",
            provider_index: int = 0,
            status: str = "completed",
        ) -> NodeDeployment:
            provider = providers[provider_index]
            return NodeDeployment(
                environment=environment,
                node_type=node_type,
                provider=provider,
                region=regions[provider_index],
                node_size=sizes[provider_index],
                panel_type=panel,
                hostname=f"{environment}-{node_type}-{provider.code}-de-fsn1-{number:03d}",
                node_number=number,
                status=status,
                display_name=SEARCH,
            )

        matching = NodeDeployment.objects.bulk_create([deployment(number) for number in range(1, 27)])
        now = timezone.now()
        for number, item in enumerate(matching):
            item.created_at = now - timedelta(minutes=number)
        NodeDeployment.objects.bulk_update(matching, ["created_at"])
        search_decoy = deployment(31)
        search_decoy.display_name = "Other deployment"
        excluded = NodeDeployment.objects.bulk_create(
            [
                deployment(27, environment="stg"),
                deployment(28, node_type="vps"),
                deployment(29, provider_index=1),
                deployment(30, status="failed"),
                search_decoy,
            ]
        )
        url = reverse("infrastructure:deployment_list")
        parameters = {
            "environment": "prd",
            "node_type": "sha",
            "provider": str(providers[0].pk),
            "status": "completed",
            "search": SEARCH,
            "facet": ["one", "two"],
            "page": ["7", "1"],
        }
        response = self.client.get(url, parameters)
        first_page: Page[NodeDeployment] = response.context["deployments_page"]
        self.assertEqual(first_page.paginator.count, 26)
        self.assertEqual([item.pk for item in first_page], [item.pk for item in matching[:25]])

        next_response = self.client.get(urljoin(url, next_page_url(self, response)))
        self.assertEqual(next_response.status_code, 200)
        self.assertEqual(
            dict(next_response.wsgi_request.GET.lists()),
            {
                "page": ["2"],
                "environment": ["prd"],
                "node_type": ["sha"],
                "provider": [str(providers[0].pk)],
                "status": ["completed"],
                "search": [SEARCH],
                "facet": ["one", "two"],
            },
        )
        second_page: Page[NodeDeployment] = next_response.context["deployments_page"]
        self.assertEqual(second_page.number, 2)
        self.assertEqual(second_page.paginator.count, 26)
        self.assertEqual([item.pk for item in second_page], [matching[25].pk])
        self.assertContains(next_response, matching[25].hostname)
        for item in [*matching[:25], *excluded]:
            self.assertNotContains(next_response, item.hostname)
