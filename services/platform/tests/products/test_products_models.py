"""
🔒 Model Security Integration Tests for Products App
Tests security features integrated into Django models.
"""

from decimal import Decimal
from unittest.mock import patch
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

from apps.products.models import Product, ProductPrice, validate_json_field, validate_product_config
from apps.billing.models import Currency

User = get_user_model()


class ProductSecurityTests(TestCase):
    """🔒 Tests for Product model security"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True
        )
    
    def test_json_field_size_validation(self):
        """🔒 Test that JSON fields reject oversized data"""
        product = Product(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting",
            tags=["x" * 5000] * 10  # Large JSON array
        )
        
        with self.assertRaises(ValidationError):
            product.clean()
    
    def test_json_field_depth_validation(self):
        """🔒 Test that JSON fields reject deeply nested data"""
        # Create 12 levels deep (over 10 limit)
        deep_config = {}
        current = deep_config
        for i in range(12):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        
        product = Product(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting",
            module_config=deep_config
        )
        
        with self.assertRaises(ValidationError):
            product.clean()
    
    def test_dangerous_config_patterns_blocked(self):
        """🔒 Test that dangerous patterns in config are blocked"""
        dangerous_configs = [
            {"command": "eval('malicious code')"},
            {"script": "<script>alert('xss')</script>"},
            {"shell": "os.system('rm -rf /')"},
            {"import": "__import__('subprocess')"}
        ]
        
        for config in dangerous_configs:
            product = Product(
                slug="test-dangerous",
                name="Test Product",
                product_type="shared_hosting",
                module_config=config
            )
            
            with self.assertRaises(ValidationError, msg=f"Failed to block: {config}"):
                product.clean()
    
    def test_sensitive_config_keys_blocked(self):
        """🔒 Test that sensitive keys are blocked in configuration"""
        sensitive_configs = [
            {"password": "secret123"},
            {"api_key": "key123"},
            {"private_token": "token123"},
            {"admin_pass": "admin123"}
        ]
        
        for config in sensitive_configs:
            product = Product(
                slug="test-sensitive",
                name="Test Product",
                product_type="shared_hosting",
                module_config=config
            )
            
            with self.assertRaises(ValidationError, msg=f"Failed to block: {config}"):
                product.clean()
    
    def test_text_field_length_validation(self):
        """🔒 Test that text fields have length limits"""
        product = Product(
            slug="test-long",
            name="Test Product",
            product_type="shared_hosting",
            description="x" * 15000  # Over 10KB limit
        )
        
        with self.assertRaises(ValidationError):
            product.clean()
    
    def test_safe_product_passes_validation(self):
        """✅ Test that safe product passes validation"""
        product = Product(
            slug="safe-product",
            name="Safe Product",
            description="This is a safe product description",
            product_type="shared_hosting",
            module_config={"server": "cpanel", "disk_space": "10GB"},
            tags=["hosting", "shared", "cpanel"],
            meta={"category": "basic", "popularity": 5}
        )
        
        try:
            product.clean()  # Should not raise ValidationError
        except ValidationError as e:
            self.fail(f"Safe product failed validation: {e}")
    
    @patch('apps.products.models.logger')
    def test_security_logging_on_validation(self, mock_logger):
        """🔒 Test that product validation is logged"""
        product = Product(
            slug="logged-product",
            name="Test Product",
            product_type="vps"
        )
        
        product.clean()
        
        # Should log security validation
        mock_logger.info.assert_called()
        call_args = str(mock_logger.info.call_args)
        self.assertIn("product_validation", call_args)


class ProductPriceSecurityTests(TestCase):
    """🔒 Tests for ProductPrice model security"""
    
    def setUp(self):
        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting"
        )
        
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON"
        )
    
    def test_negative_prices_blocked(self):
        """🔒 Test that negative prices are blocked"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=-1000  # Negative price
        )
        
        with self.assertRaises(ValidationError):
            price.clean()
    
    def test_extremely_large_prices_blocked(self):
        """🔒 Test that unrealistic prices are blocked"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=200000000  # 2 million - too large
        )
        
        with self.assertRaises(ValidationError):
            price.clean()
    
    def test_invalid_discount_percentage_blocked(self):
        """🔒 Test that invalid discount percentages are blocked"""
        # Test negative semiannual discount
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10000,
            semiannual_discount_percent=Decimal("-5.00")
        )

        with self.assertRaises(ValidationError):
            price.clean()

        # Test over 100% semiannual discount
        price.semiannual_discount_percent = Decimal("150.00")

        with self.assertRaises(ValidationError):
            price.clean()

        # Test negative annual discount
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10000,
            annual_discount_percent=Decimal("-5.00")
        )

        with self.assertRaises(ValidationError):
            price.clean()

        # Test over 100% annual discount
        price.annual_discount_percent = Decimal("150.00")

        with self.assertRaises(ValidationError):
            price.clean()
    
    def test_invalid_quantity_limits_blocked(self):
        """🔒 Test that invalid quantity limits are blocked"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10000,
            minimum_quantity=0  # Less than 1
        )
        
        with self.assertRaises(ValidationError):
            price.clean()
            
        # Test max less than min
        price.minimum_quantity = 5
        price.maximum_quantity = 3
        
        with self.assertRaises(ValidationError):
            price.clean()
    
    def test_promotional_pricing_validation(self):
        """🔒 Test that promotional pricing logic is validated"""
        from django.utils import timezone
        from datetime import timedelta

        # Test promo price without valid until date
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10000,
            promo_price_cents=8000
            # Missing promo_valid_until
        )
        
        with self.assertRaises(ValidationError):
            price.clean()
            
        # Test past promo valid until date
        price.promo_valid_until = timezone.now() - timedelta(days=1)
        
        with self.assertRaises(ValidationError):
            price.clean()
    
    def test_safe_price_passes_validation(self):
        """✅ Test that safe price passes validation"""
        from django.utils import timezone
        from datetime import timedelta

        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2999,  # 29.99
            setup_cents=500,    # 5.00 setup fee
            semiannual_discount_percent=Decimal("10.00"),
            annual_discount_percent=Decimal("15.00"),
            minimum_quantity=1,
            maximum_quantity=10,
            promo_price_cents=2499,  # 24.99 promo
            promo_valid_until=timezone.now() + timedelta(days=30)
        )
        
        try:
            price.clean()  # Should not raise ValidationError
        except ValidationError as e:
            self.fail(f"Safe price failed validation: {e}")
    
    @patch('apps.products.models.logger')
    def test_security_logging_on_validation(self, mock_logger):
        """🔒 Test that price validation is logged"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=10000
        )
        
        price.clean()
        
        # Should log security validation
        mock_logger.info.assert_called()
        call_args = str(mock_logger.info.call_args)
        self.assertIn("product_price_validation", call_args)

    def test_pricing_calculations(self):
        """✅ Test simplified pricing model calculations"""
        from django.utils import timezone
        from datetime import timedelta

        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=3000,  # 30.00 per month
            semiannual_discount_percent=Decimal("10.00"),  # 10% off
            annual_discount_percent=Decimal("20.00"),  # 20% off
        )

        # Test monthly price calculation
        self.assertEqual(price.monthly_price, Decimal("30.00"))

        # Test semiannual calculation (30.00 × 6 = 180.00, 10% off = 162.00)
        expected_semiannual = Decimal("30.00") * 6 * Decimal("0.90")  # 10% discount
        self.assertEqual(price.semiannual_price, expected_semiannual)

        # Test annual calculation (30.00 × 12 = 360.00, 20% off = 288.00)
        expected_annual = Decimal("30.00") * 12 * Decimal("0.80")  # 20% discount
        self.assertEqual(price.annual_price, expected_annual)

        # Test discount detection
        self.assertTrue(price.has_semiannual_discount)
        self.assertTrue(price.has_annual_discount)

    def test_pricing_calculations_without_discounts(self):
        """✅ Test pricing calculations without discounts"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2500,  # 25.00 per month
            semiannual_discount_percent=Decimal("0.00"),  # No discount
            annual_discount_percent=Decimal("0.00"),  # No discount
        )

        # Test calculations without discounts
        self.assertEqual(price.monthly_price, Decimal("25.00"))
        self.assertEqual(price.semiannual_price, Decimal("25.00") * 6)  # 150.00
        self.assertEqual(price.annual_price, Decimal("25.00") * 12)  # 300.00

        # Test discount detection
        self.assertFalse(price.has_semiannual_discount)
        self.assertFalse(price.has_annual_discount)

    def test_get_price_for_period(self):
        """✅ Test get_price_for_period method"""
        price = ProductPrice(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=4000,  # 40.00 per month
            semiannual_discount_percent=Decimal("15.00"),  # 15% off
            annual_discount_percent=Decimal("25.00"),  # 25% off
        )

        # Test different billing periods
        self.assertEqual(price.get_price_for_period("monthly"), Decimal("40.00"))

        # Semiannual: 40 × 6 = 240, 15% off = 204.00
        expected_semiannual = Decimal("240.00") * Decimal("0.85")
        self.assertEqual(price.get_price_for_period("semiannual"), expected_semiannual)

        # Annual: 40 × 12 = 480, 25% off = 360.00
        expected_annual = Decimal("480.00") * Decimal("0.75")
        self.assertEqual(price.get_price_for_period("annual"), expected_annual)

        # Test unsupported period
        with self.assertRaises(ValueError):
            price.get_price_for_period("quarterly")


class SecurityValidationFunctionTests(TestCase):
    """🔒 Tests for security validation functions"""
    
    def test_validate_json_field_size_limits(self):
        """🔒 Test JSON size validation"""
        large_data = {"data": "x" * 15000}  # Over 10KB
        
        with self.assertRaises(ValidationError) as cm:
            validate_json_field(large_data, "test field")
        
        self.assertIn("too large", str(cm.exception))
    
    def test_validate_json_field_depth_limits(self):
        """🔒 Test JSON depth validation"""
        # Create 12 levels deep
        deep_data = {}
        current = deep_data
        for i in range(12):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        
        with self.assertRaises(ValidationError) as cm:
            validate_json_field(deep_data, "test field")
        
        self.assertIn("too deep", str(cm.exception))
    
    def test_validate_product_config_dangerous_patterns(self):
        """🔒 Test product config dangerous pattern detection"""
        dangerous_config = {
            "command": "eval('malicious')",
            "script": "os.system('rm -rf /')"
        }
        
        with self.assertRaises(ValidationError):
            validate_product_config(dangerous_config)
    
    def test_validate_product_config_sensitive_keys(self):
        """🔒 Test product config sensitive key detection"""
        sensitive_config = {
            "mysql_password": "secret123",
            "api_key": "key123"
        }
        
        with self.assertRaises(ValidationError):
            validate_product_config(sensitive_config)
    
    def test_safe_data_passes_validation(self):
        """✅ Test that safe data passes all validations"""
        safe_json = {
            "server_type": "cpanel",
            "disk_space": "10GB",
            "bandwidth": "unlimited",
            "features": ["email", "mysql", "php"]
        }
        
        safe_config = {
            "panel": "cpanel",
            "php_version": "8.1",
            "mysql_version": "8.0"
        }
        
        try:
            validate_json_field(safe_json, "safe JSON")
            validate_product_config(safe_config)
        except ValidationError as e:
            self.fail(f"Safe data failed validation: {e}")