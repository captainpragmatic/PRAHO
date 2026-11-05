"""Customer output distinguishes requested and actually verified temporary relief."""

from django.test import TransactionTestCase

from apps.api.services.serializers import ServiceDetailSerializer, ServiceListSerializer
from apps.provisioning.models import Service
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class HostingRaiseSurfaceTests(HostingRaiseFixture, TransactionTestCase):
    def serialized(self, serializer):
        service = Service.objects.select_related("customer", "service_plan", "currency", "hosting_limits").get(
            pk=self.service.pk
        )
        return serializer(service).data

    def test_customer_raise_data_tracks_real_grant_then_verified_application_without_changing_allowance(self) -> None:
        application = self.grant()
        for serializer in (ServiceDetailSerializer, ServiceListSerializer):
            data = self.serialized(serializer)
            self.assertIn("hosting_raise", data)
            self.assertEqual((data["hosting_raise"]["state"], data["hosting_raise"]["extra_mib"]), ("requested", 1280))
            self.assertEqual(data["hosting_limits"]["operational"]["disk_mib"], 5120)
        self.assertEqual(self.apply(application), "completed")
        for serializer in (ServiceDetailSerializer, ServiceListSerializer):
            data = self.serialized(serializer)
            self.assertEqual((data["hosting_raise"]["state"], data["hosting_raise"]["extra_mib"]), ("verified", 1280))
            self.assertEqual(data["hosting_limits"]["operational"]["disk_mib"], 5120)
            self.assertEqual(set(data["hosting_raise"]), {"state", "extra_mib", "expires_at", "revision"})
