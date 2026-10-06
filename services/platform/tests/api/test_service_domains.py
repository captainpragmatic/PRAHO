"""Service domains are read through authenticated customer service ownership."""

from tests.helpers.service_domains import ServiceDomainsFixture


class ServiceDomainsAPITests(ServiceDomainsFixture):
    def test_own_service_returns_relationships_with_full_names(self) -> None:
        response = self.portal_post(f"/api/services/{self.service.pk}/domains/", self._body())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["success"], True)
        self.assertCountEqual(
            response.json()["data"]["domains"],
            [
                {
                    "id": self.primary.pk,
                    "name": "wp8-example.com",
                    "status": "active",
                    "domain_type": "primary",
                    "subdomain": "",
                    "is_active": True,
                    "ssl_enabled": True,
                },
                {
                    "id": self.subdomain.pk,
                    "name": "blog.wp8-example.com",
                    "status": "active",
                    "domain_type": "subdomain",
                    "subdomain": "blog",
                    "is_active": False,
                    "ssl_enabled": False,
                },
            ],
        )

    def test_another_customers_service_is_not_disclosed(self) -> None:
        response = self.portal_post(f"/api/services/{self.other_service.pk}/domains/", self._body())
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"success": False, "error": "Service not found or access denied"})
        self.assertNotIn("wp8-private.com", response.content.decode())

    def test_missing_user_is_denied(self) -> None:
        response = self.portal_post(f"/api/services/{self.service.pk}/domains/", {"customer_id": self.customer.pk})
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json(), {"success": False, "error": "Invalid request format"})

    def test_a_service_without_domains_returns_an_authoritative_empty_list(self) -> None:
        self.service.domains.all().delete()
        response = self.portal_post(f"/api/services/{self.service.pk}/domains/", self._body())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json(), {"success": True, "data": {"domains": []}})
