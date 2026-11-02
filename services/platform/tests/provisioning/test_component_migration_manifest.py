"""A component review cannot authorize the whole home, mail, unclassified writers or shared databases."""

from copy import deepcopy

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.provisioning.component_migration_manifest import ComponentManifest


def component_manifest():
    return {
        "schema": 1,
        "source": {
            "server_uuid": "4b982745-01e7-4033-971b-85e5f3c6bdf3",
            "connection_identity": "a" * 64,
            "domain_id": "123456789",
            "domain": "example.test",
            "owner": "customer",
            "home": "/home/customer",
            "webmin": "2.670",
            "virtualmin": "8.3.0",
        },
        "paths": [
            {
                "relative": "public_html",
                "purpose": "application",
                "device": 12,
                "inode": 100,
                "bytes": 300,
                "tree_digest": "b" * 64,
            }
        ],
        "databases": [
            {
                "name": "customer_web",
                "bytes": 400,
                "charset": "utf8mb4",
                "collation": "utf8mb4_general_ci",
                "principals": [
                    {
                        "user": "webapp",
                        "host": "localhost",
                        "locked": False,
                        "auth_digest": "c" * 64,
                        "grants_digest": "d" * 64,
                    }
                ],
                "isolated": True,
            }
        ],
        "writers": [{"kind": "php_fpm_pool", "identity": "123456789", "digest": "e" * 64}],
        "routing": {"website_names": ["example.test", "www.example.test"], "digest": "f" * 64},
        "retained": {
            "services": ["mail", "dns", "authentication"],
            "database_names": ["customer_mail"],
            "digest": "0" * 64,
        },
        "preparation": [],
    }


class ComponentManifestTests(SimpleTestCase):
    def test_exact_scope_and_selected_size_survive_roundtrip(self):
        facts = component_manifest()
        manifest = ComponentManifest.parse(facts)
        self.assertEqual(manifest.as_json(), facts)
        self.assertEqual(manifest.transfer_bytes, 700)
        self.assertEqual(manifest.selected_paths, ("public_html",))
        self.assertEqual(manifest.selected_databases, ("customer_web",))
        facts["paths"][0]["relative"] = "Maildir"
        self.assertEqual(manifest.selected_paths, ("public_html",))

    def test_home_mail_dotfiles_traversal_and_overlapping_roots_refused(self):
        for path in (
            ".",
            "",
            "/home/customer",
            "../other",
            "public_html/../Maildir",
            "Maildir",
            "mail",
            "homes",
            ".ssh",
            ".backup",
        ):
            facts = component_manifest()
            facts["paths"][0]["relative"] = path
            with self.subTest(path=path), self.assertRaises(ValidationError):
                ComponentManifest.parse(facts)
        facts = component_manifest()
        facts["paths"].append({**facts["paths"][0], "relative": "public_html/uploads"})
        with self.assertRaises(ValidationError):
            ComponentManifest.parse(facts)

    def test_selected_database_must_be_isolated_from_retained_services(self):
        for change in ("shared", "retained", "unproven"):
            facts = component_manifest()
            if change == "shared":
                facts["databases"][0]["isolated"] = False
            elif change == "retained":
                facts["retained"]["database_names"].append("customer_web")
            else:
                facts["databases"][0]["principals"] = []
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ComponentManifest.parse(facts).assert_ready()

    def test_mail_aliases_and_unresolved_dependencies_require_preparation(self):
        for field in ("mail_alias", "mx", "writer"):
            facts = component_manifest()
            if field == "mail_alias":
                facts["routing"]["website_names"].append("mail.example.test")
            else:
                facts["preparation"] = [
                    "MX points at the website apex" if field == "mx" else "Unclassified source writer"
                ]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                ComponentManifest.parse(facts).assert_ready()

    def test_unknown_fields_and_unbounded_values_cannot_hide_secret_metadata(self):
        facts = component_manifest()
        variations = [deepcopy(facts) for _ in range(4)]
        variations[0]["source"]["password"] = "must not be persisted"
        variations[1]["writers"][0]["command"] = "script with potentially secret arguments"
        variations[2]["paths"][0]["bytes"] = True
        variations[3]["preparation"] = ["x" * 2001]
        for variation in variations:
            with self.assertRaises(ValidationError):
                ComponentManifest.parse(variation)

    def test_digest_binds_retained_services_writers_and_routing(self):
        facts = component_manifest()
        digest = ComponentManifest.parse(facts).digest
        for section in ("retained", "routing"):
            modified = deepcopy(facts)
            modified[section]["digest"] = "1" * 64
            self.assertNotEqual(ComponentManifest.parse(modified).digest, digest)
        facts["writers"][0]["digest"] = "2" * 64
        self.assertNotEqual(ComponentManifest.parse(facts).digest, digest)

    def test_live_website_data_can_grow_without_expanding_the_approved_component_scope(self):
        facts = component_manifest()
        original = ComponentManifest.parse(facts)
        facts["paths"][0]["bytes"] += 900
        facts["paths"][0]["tree_digest"] = "3" * 64
        facts["databases"][0]["bytes"] += 800
        fresh = ComponentManifest.parse(facts)
        self.assertNotEqual(original.digest, fresh.digest)
        self.assertEqual(original.authority_digest, fresh.authority_digest)
        self.assertEqual(fresh.transfer_bytes, 2400)
        facts["paths"][0]["inode"] += 1
        self.assertNotEqual(original.authority_digest, ComponentManifest.parse(facts).authority_digest)

    def test_database_grants_and_retained_dependencies_remain_part_of_operator_authority(self):
        facts = component_manifest()
        original = ComponentManifest.parse(facts).authority_digest
        facts["databases"][0]["principals"][0]["grants_digest"] = "4" * 64
        self.assertNotEqual(ComponentManifest.parse(facts).authority_digest, original)

    def test_unqualified_native_callbacks_require_preparation(self):
        facts = component_manifest()
        facts["source"]["virtualmin"] = "99.0.0"
        with self.assertRaises(ValidationError):
            ComponentManifest.parse(facts).assert_ready()
