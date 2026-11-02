"""Provider resource discovery must be complete and never infer ownership from attachment."""

from unittest.mock import Mock

from django.test import SimpleTestCase

from apps.infrastructure.cloud_resource_inventory import CloudResourceClient, ResourceResponse


class ResourceInventoryTests(SimpleTestCase):
    def test_vultr_creation_tags_and_snapshot_dependencies_are_preserved(self):
        request = Mock(
            return_value=ResourceResponse(
                200,
                {
                    "instances": [
                        {
                            "id": "vm",
                            "status": "active",
                            "label": "correlation",
                            "tags": ["praho-deployment=correlation", "managed-by=praho"],
                            "snapshot_id": "source-snapshot",
                            "image_id": "",
                        }
                    ],
                    "meta": {"links": {"next": ""}},
                },
            )
        )
        resource = CloudResourceClient("vultr", request).list_collection("instances")[0]
        self.assertEqual(resource.labels["praho-deployment"], "correlation")
        self.assertEqual(resource.source_ids, ("source-snapshot",))

    def test_vultr_volume_snapshots_have_a_separate_native_route_and_bare_object(self):
        request = Mock(
            side_effect=[
                ResourceResponse(
                    200,
                    {
                        "snapshots": [{"id": "vs", "block_id": "volume", "state": "COMPLETE"}],
                        "meta": {"links": {"next": ""}},
                    },
                ),
                ResourceResponse(200, {"id": "vs", "block_id": "volume", "state": "COMPLETE"}),
            ]
        )
        client = CloudResourceClient("vultr", request)
        resource = client.list_collection("blocks/snapshots")[0]
        self.assertEqual(
            (resource.kind, resource.source_ids, resource.state), ("volume_snapshot", ("volume",), "complete")
        )
        self.assertEqual(client.read_exact("volume_snapshot", "vs")["block_id"], "volume")
        self.assertEqual(request.call_args.args[:2], ("GET", "/blocks/snapshots/vs"))

    def test_digitalocean_private_image_view_does_not_require_snapshot_resource_view_fields(self):
        request = Mock(
            return_value=ResourceResponse(
                200, {"images": [{"id": 91, "type": "snapshot", "status": "available", "tags": []}], "links": {}}
            )
        )
        resource = CloudResourceClient("digitalocean", request).list_collection("images")[0]
        self.assertEqual((resource.kind, resource.resource_id), ("snapshot", "91"))

    def test_hetzner_reads_every_page_and_keeps_snapshot_origin(self):
        request = Mock(
            side_effect=[
                ResourceResponse(
                    200,
                    {
                        "images": [
                            {"id": 31, "type": "backup", "status": "available", "created_from": {"id": 7}, "labels": {}}
                        ],
                        "meta": {"pagination": {"next_page": 2}},
                    },
                ),
                ResourceResponse(
                    200,
                    {
                        "images": [
                            {
                                "id": 32,
                                "type": "snapshot",
                                "status": "available",
                                "created_from": {"id": 7},
                                "labels": {},
                            }
                        ],
                        "meta": {"pagination": {"next_page": None}},
                    },
                ),
            ]
        )
        resources = CloudResourceClient("hetzner", request).list_collection("images")
        self.assertEqual([item.resource_id for item in resources], ["31", "32"])
        self.assertEqual(resources[0].kind, "backup")
        self.assertEqual(resources[0].source_ids, ("7",))
        self.assertEqual(request.call_args_list[1].kwargs["params"]["page"], 2)

    def test_digitalocean_rejects_untrusted_pagination_url(self):
        request = Mock(
            return_value=ResourceResponse(
                200, {"snapshots": [], "links": {"pages": {"next": "https://attacker.test/v2/snapshots?page=2"}}}
            )
        )
        with self.assertRaisesRegex(ValueError, "pagination"):
            CloudResourceClient("digitalocean", request).list_collection("snapshots")
        self.assertEqual(request.call_count, 1)

    def test_missing_list_or_permission_failure_is_not_empty_inventory(self):
        for reply in (ResourceResponse(403, {}), ResourceResponse(200, {}), ResourceResponse(200, {"blocks": None})):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                CloudResourceClient("vultr", Mock(return_value=reply)).list_collection("blocks")

    def test_attached_volume_does_not_become_owned_and_unknown_snapshots_keep_unknown_origin(self):
        request = Mock(
            return_value=ResourceResponse(
                200,
                {
                    "blocks": [
                        {"id": "vol", "attached_to_instance": "vm", "label": "looks-like-praho", "status": "active"}
                    ],
                    "meta": {"links": {"next": ""}},
                },
            )
        )
        resource = CloudResourceClient("vultr", request).list_collection("blocks")[0]
        self.assertEqual(resource.attached_to, ("vm",))
        self.assertEqual(resource.labels, {})
        snapshot = CloudResourceClient(
            "vultr",
            Mock(
                return_value=ResourceResponse(
                    200,
                    {
                        "snapshots": [{"id": "snap", "description": "vm", "status": "complete"}],
                        "meta": {"links": {"next": ""}},
                    },
                )
            ),
        ).list_collection("snapshots")[0]
        self.assertEqual(snapshot.source_ids, ())

    def test_repeated_page_or_duplicate_id_refuses_partial_inventory(self):
        for payload in (
            {"volumes": [], "meta": {"pagination": {"next_page": 1}}},
            {
                "volumes": [{"id": 1, "server": None}, {"id": 1, "server": None}],
                "meta": {"pagination": {"next_page": None}},
            },
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                CloudResourceClient("hetzner", Mock(return_value=ResourceResponse(200, payload))).list_collection(
                    "volumes"
                )

    def test_delete_receipt_requires_exact_authoritative_absence(self):
        request = Mock(side_effect=[ResourceResponse(204, None), ResourceResponse(200, {"snapshot": {"id": "s"}})])
        client = CloudResourceClient("vultr", request, poll_timeout=0)
        self.assertFalse(client.delete_exact("snapshot", "s").is_ok())
        request = Mock(side_effect=[ResourceResponse(204, None), ResourceResponse(404, {})])
        self.assertTrue(CloudResourceClient("vultr", request, poll_timeout=0).delete_exact("snapshot", "s").is_ok())

    def test_error_text_never_proves_absence(self):
        request = Mock(side_effect=RuntimeError("not found 404"))
        self.assertTrue(CloudResourceClient("vultr", request).delete_exact("snapshot", "s").is_err())

    def test_conversion_cannot_dispatch_snapshot_create_or_claim_pending_snapshot_ready(self):
        request = Mock(
            side_effect=[
                ResourceResponse(200, {"image": {"id": 3, "type": "backup", "status": "available"}}),
                ResourceResponse(200, {"image": {"id": 3}}),
                ResourceResponse(200, {"image": {"id": 3, "type": "snapshot", "status": "creating"}}),
            ]
        )
        result = CloudResourceClient("hetzner", request, poll_timeout=0).retain_backup("3")
        self.assertTrue(result.is_err())
        self.assertEqual(request.call_args_list[1].args[:2], ("PUT", "/images/3"))
        self.assertEqual(request.call_args_list[1].kwargs["body"], {"type": "snapshot"})
