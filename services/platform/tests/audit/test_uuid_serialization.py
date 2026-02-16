"""
Test UUID serialization fix for audit system.
Ensures that UUID objects can be properly serialized in audit metadata.
"""

from datetime import datetime
from decimal import Decimal
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.audit.services import AuditContext, AuditEventData, AuditJSONEncoder, AuditService, serialize_metadata


class UUIDSerializationTestCase(TestCase):
    """Test UUID serialization functionality in audit system"""

    def test_audit_json_encoder_handles_uuid(self):
        """Test that AuditJSONEncoder can handle UUID objects"""
        import json

        test_uuid = uuid4()
        test_data = {'id': test_uuid}

        # This should not raise TypeError: Object of type UUID is not JSON serializable
        result = json.dumps(test_data, cls=AuditJSONEncoder)
        self.assertIsInstance(result, str)

        # Verify the UUID was converted to string
        parsed = json.loads(result)
        self.assertEqual(parsed['id'], str(test_uuid))

    def test_audit_json_encoder_handles_complex_types(self):
        """Test that AuditJSONEncoder can handle various complex types"""
        import json

        test_data = {
            'uuid_field': uuid4(),
            'datetime_field': timezone.now(),
            'decimal_field': Decimal('123.45'),
            'string_field': 'test',
            'number_field': 42,
            'boolean_field': True,
            'none_field': None,
            'nested': {
                'inner_uuid': uuid4(),
                'inner_decimal': Decimal('99.99')
            }
        }

        # This should not raise any serialization errors
        result = json.dumps(test_data, cls=AuditJSONEncoder)
        self.assertIsInstance(result, str)

        # Verify all values were properly serialized
        parsed = json.loads(result)
        self.assertIsInstance(parsed['uuid_field'], str)
        self.assertIsInstance(parsed['datetime_field'], str)
        self.assertIsInstance(parsed['decimal_field'], str)
        self.assertEqual(parsed['string_field'], 'test')
        self.assertEqual(parsed['number_field'], 42)
        self.assertTrue(parsed['boolean_field'])
        self.assertIsNone(parsed['none_field'])
        self.assertIsInstance(parsed['nested']['inner_uuid'], str)
        self.assertIsInstance(parsed['nested']['inner_decimal'], str)

    def test_serialize_metadata_function(self):
        """Test the serialize_metadata helper function"""

        test_metadata = {
            'invoice_id': uuid4(),
            'user_id': uuid4(),
            'amount': Decimal('150.00'),
            'timestamp': timezone.now()
        }

        # This should not raise any errors
        result = serialize_metadata(test_metadata)

        # Verify the result is a dict with serializable values
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), len(test_metadata))

        # All values should be JSON-serializable primitives
        for key, value in result.items():
            self.assertIn(type(value), [str, int, float, bool, type(None), list, dict],
                         f"Value for {key} is not JSON-serializable: {type(value)}")

    def test_serialize_metadata_with_empty_dict(self):
        """Test serialize_metadata with empty metadata"""
        result = serialize_metadata({})
        self.assertEqual(result, {})

    def test_serialize_metadata_with_none(self):
        """Test serialize_metadata with None input"""
        result = serialize_metadata(None)
        self.assertEqual(result, {})

    def test_audit_service_with_uuid_metadata(self):
        """Test that AuditService can handle metadata containing UUID objects"""

        metadata_with_uuids = {
            'invoice_id': uuid4(),
            'transaction_id': uuid4(),
            'amount': Decimal('200.00'),
            'processed_at': timezone.now()
        }

        context = AuditContext(
            user=None,  # System event
            ip_address='127.0.0.1',
            metadata=metadata_with_uuids
        )

        event_data = AuditEventData(
            event_type='test_uuid_metadata',
            description='Testing UUID serialization in audit events'
        )

        # This should not raise "TypeError: Object of type UUID is not JSON serializable"
        audit_event = AuditService.log_event(event_data, context)

        # Verify the audit event was created successfully
        self.assertIsNotNone(audit_event.id)
        self.assertEqual(audit_event.action, 'test_uuid_metadata')

        # Verify metadata was properly serialized and stored
        stored_metadata = audit_event.metadata
        self.assertIsInstance(stored_metadata, dict)
        self.assertEqual(len(stored_metadata), len(metadata_with_uuids))

        # All stored values should be strings (serialized)
        for key, value in stored_metadata.items():
            if key in ['invoice_id', 'transaction_id', 'amount', 'processed_at']:
                self.assertIsInstance(value, str, f"Value for {key} should be serialized to string")

    def test_serialize_metadata_error_handling(self):
        """Test that serialize_metadata handles serialization errors gracefully"""

        # Create an object that might cause serialization issues
        class NonSerializable:
            def __init__(self):
                self.circular_ref = self

            def __str__(self):
                return "NonSerializable object"

        problematic_metadata = {
            'normal_field': 'test',
            'uuid_field': uuid4(),  # This should work
            'problem_field': NonSerializable()  # This might cause issues
        }

        # serialize_metadata should handle this gracefully
        result = serialize_metadata(problematic_metadata)

        # Should return a dict (either successfully serialized or error info)
        self.assertIsInstance(result, dict)

        # If it failed, should contain error information
        if 'serialization_error' in result:
            self.assertIn('original_keys', result)
            self.assertIn('timestamp', result)
        else:
            # If it succeeded, all fields should be present
            self.assertIn('normal_field', result)
            self.assertIn('uuid_field', result)
