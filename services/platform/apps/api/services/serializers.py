# ===============================================================================
# SERVICES API SERIALIZERS - CUSTOMER HOSTING SERVICES 📦
# ===============================================================================

from decimal import Decimal
from typing import Any, ClassVar

from django.utils import timezone
from rest_framework import serializers

from apps.provisioning.service_models import Server, Service, ServicePlan


class ServicePlanListSerializer(serializers.ModelSerializer):
    """Service plan serializer for service listings"""
    
    # Plan display information
    plan_type_display = serializers.CharField(source='get_plan_type_display', read_only=True)
    
    class Meta:
        model = ServicePlan
        fields: ClassVar = [
            'id', 'name', 'plan_type', 'plan_type_display', 'description',
            'price_monthly', 'price_quarterly', 'price_annual', 'setup_fee',
            'disk_space_gb', 'bandwidth_gb', 'email_accounts', 'databases',
            'domains', 'cpu_cores', 'ram_gb'
        ]


class ServerListSerializer(serializers.ModelSerializer):
    """Server serializer for service listings"""
    
    # Server display information
    server_type_display = serializers.CharField(source='get_server_type_display', read_only=True)
    
    class Meta:
        model = Server
        fields: ClassVar = [
            'id', 'name', 'hostname', 'server_type', 'server_type_display',
            'primary_ip', 'location', 'datacenter', 'status'
        ]


class ServiceListSerializer(serializers.ModelSerializer):
    """Service list serializer for customer hosting services listing"""
    
    # Related fields
    customer_name = serializers.CharField(source='customer.company_name', read_only=True)
    service_plan_name = serializers.CharField(source='service_plan.name', read_only=True)
    service_plan_type = serializers.CharField(source='service_plan.plan_type', read_only=True)
    service_plan_type_display = serializers.CharField(source='service_plan.get_plan_type_display', read_only=True)
    server_name = serializers.CharField(source='server.name', read_only=True)
    
    # Status display
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    billing_cycle_display = serializers.CharField(source='get_billing_cycle_display', read_only=True)
    
    # Status colors for UI
    status_color = serializers.SerializerMethodField()
    
    # Resource usage
    disk_usage_gb = serializers.SerializerMethodField()
    bandwidth_usage_gb = serializers.SerializerMethodField()
    
    # Pricing
    monthly_price = serializers.SerializerMethodField()
    
    # Service lifecycle
    is_overdue = serializers.ReadOnlyField()
    days_until_expiry = serializers.ReadOnlyField()
    is_active = serializers.SerializerMethodField()
    
    # Dates
    next_billing_date = serializers.SerializerMethodField()
    
    class Meta:
        model = Service
        fields: ClassVar = [
            'id', 'service_name', 'domain', 'username', 'status', 'status_display', 'status_color',
            'billing_cycle', 'billing_cycle_display', 'price', 'monthly_price', 'setup_fee_paid',
            'customer_name', 'service_plan_name', 'service_plan_type', 'service_plan_type_display',
            'server_name', 'auto_renew', 'is_overdue', 'days_until_expiry', 'is_active',
            'disk_usage_gb', 'bandwidth_usage_gb', 'email_accounts_used', 'databases_used',
            'next_billing_date', 'created_at', 'activated_at', 'expires_at', 'updated_at'
        ]
    
    def get_status_color(self, obj: Service) -> str:
        """Get status color for UI"""
        status_colors = {
            'active': '#10B981',      # Green
            'suspended': '#EF4444',   # Red  
            'pending': '#F59E0B',     # Yellow
            'provisioning': '#3B82F6', # Blue
            'terminated': '#6B7280',   # Gray
            'expired': '#F97316'       # Orange
        }
        return status_colors.get(obj.status, '#6B7280')
    
    def get_disk_usage_gb(self, obj: Service) -> float:
        """Convert disk usage from MB to GB"""
        return round(obj.disk_usage_mb / 1024, 2)
    
    def get_bandwidth_usage_gb(self, obj: Service) -> float:
        """Convert bandwidth usage from MB to GB"""
        return round(obj.bandwidth_usage_mb / 1024, 2)
    
    def get_monthly_price(self, obj: Service) -> Decimal:
        """Get monthly equivalent price"""
        return obj.service_plan.get_monthly_equivalent_price(obj.billing_cycle)
    
    def get_is_active(self, obj: Service) -> bool:
        """Check if service is active"""
        return obj.status == 'active'
    
    def get_next_billing_date(self, obj: Service) -> str | None:
        """Get next billing date"""
        next_date = obj.get_next_billing_date()
        return next_date.isoformat() if next_date else None


class ServiceDetailSerializer(serializers.ModelSerializer):
    """Service detail serializer for complete service information"""
    
    # Related objects with full detail
    service_plan = ServicePlanListSerializer(read_only=True)
    server = ServerListSerializer(read_only=True)
    
    # Customer information (limited for customer API)
    customer_name = serializers.CharField(source='customer.company_name', read_only=True)
    customer_cui = serializers.CharField(source='customer.cui', read_only=True)
    customer_contact_email = serializers.CharField(source='customer.contact_email', read_only=True)
    customer_contact_phone = serializers.CharField(source='customer.primary_phone', read_only=True)
    
    # Status display
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    billing_cycle_display = serializers.CharField(source='get_billing_cycle_display', read_only=True)
    status_color = serializers.SerializerMethodField()
    
    # Resource usage
    disk_usage_gb = serializers.SerializerMethodField()
    bandwidth_usage_gb = serializers.SerializerMethodField()
    disk_usage_percentage = serializers.SerializerMethodField()
    bandwidth_usage_percentage = serializers.SerializerMethodField()
    
    # Pricing information
    monthly_price = serializers.SerializerMethodField()
    total_monthly_cost = serializers.SerializerMethodField()
    vat_amount = serializers.SerializerMethodField()
    
    # Service lifecycle
    is_overdue = serializers.ReadOnlyField()
    days_until_expiry = serializers.ReadOnlyField()
    next_billing_date = serializers.SerializerMethodField()
    service_age_days = serializers.SerializerMethodField()
    
    # Features and limits from service plan
    features = serializers.SerializerMethodField()
    
    # Customer permissions
    permissions = serializers.SerializerMethodField()
    
    class Meta:
        model = Service
        fields: ClassVar = [
            'id', 'service_name', 'domain', 'username', 'status', 'status_display', 'status_color',
            'billing_cycle', 'billing_cycle_display', 'price', 'monthly_price', 'total_monthly_cost',
            'vat_amount', 'setup_fee_paid', 'auto_renew',
            
            # Customer info
            'customer_name', 'customer_cui', 'customer_contact_email', 'customer_contact_phone',
            
            # Related objects
            'service_plan', 'server',
            
            # Usage and limits
            'disk_usage_gb', 'bandwidth_usage_gb', 'disk_usage_percentage', 'bandwidth_usage_percentage',
            'email_accounts_used', 'databases_used', 'features',
            
            # Lifecycle
            'is_overdue', 'days_until_expiry', 'next_billing_date', 'service_age_days',
            'created_at', 'activated_at', 'suspended_at', 'expires_at', 'updated_at',
            
            # Admin notes (limited)
            'suspension_reason', 'permissions'
        ]
    
    def get_status_color(self, obj: Service) -> str:
        """Get status color for UI"""
        status_colors = {
            'active': '#10B981',      # Green
            'suspended': '#EF4444',   # Red  
            'pending': '#F59E0B',     # Yellow
            'provisioning': '#3B82F6', # Blue
            'terminated': '#6B7280',   # Gray
            'expired': '#F97316'       # Orange
        }
        return status_colors.get(obj.status, '#6B7280')
    
    def get_disk_usage_gb(self, obj: Service) -> float:
        """Convert disk usage from MB to GB"""
        return round(obj.disk_usage_mb / 1024, 2)
    
    def get_bandwidth_usage_gb(self, obj: Service) -> float:
        """Convert bandwidth usage from MB to GB"""
        return round(obj.bandwidth_usage_mb / 1024, 2)
    
    def get_disk_usage_percentage(self, obj: Service) -> float:
        """Calculate disk usage percentage"""
        if not obj.service_plan.disk_space_gb or obj.disk_usage_mb == 0:
            return 0.0
        
        used_gb = obj.disk_usage_mb / 1024
        return round((used_gb / obj.service_plan.disk_space_gb) * 100, 1)
    
    def get_bandwidth_usage_percentage(self, obj: Service) -> float:
        """Calculate bandwidth usage percentage"""
        if not obj.service_plan.bandwidth_gb or obj.bandwidth_usage_mb == 0:
            return 0.0
        
        used_gb = obj.bandwidth_usage_mb / 1024
        return round((used_gb / obj.service_plan.bandwidth_gb) * 100, 1)
    
    def get_monthly_price(self, obj: Service) -> Decimal:
        """Get monthly equivalent price"""
        return obj.service_plan.get_monthly_equivalent_price(obj.billing_cycle)
    
    def get_total_monthly_cost(self, obj: Service) -> Decimal:
        """Get total monthly cost including VAT"""
        from apps.common.tax_service import TaxService
        base_price = self.get_monthly_price(obj)
        vat_multiplier = Decimal('1') + TaxService.get_vat_rate('RO', as_decimal=True)
        return round(base_price * vat_multiplier, 2)  # Romanian VAT (current rate)
    
    def get_vat_amount(self, obj: Service) -> Decimal:
        """Get VAT amount"""
        from apps.common.tax_service import TaxService
        base_price = self.get_monthly_price(obj)
        vat_rate = TaxService.get_vat_rate('RO', as_decimal=True)
        return round(base_price * vat_rate, 2)  # Romanian VAT (current rate)
    
    def get_next_billing_date(self, obj: Service) -> str | None:
        """Get next billing date"""
        next_date = obj.get_next_billing_date()
        return next_date.isoformat() if next_date else None
    
    def get_service_age_days(self, obj: Service) -> int:
        """Get service age in days"""
        if obj.activated_at:
            return (timezone.now() - obj.activated_at).days
        return (timezone.now() - obj.created_at).days
    
    def get_features(self, obj: Service) -> dict[str, Any]:
        """Get service plan features and limits"""
        plan = obj.service_plan
        return {
            'disk_space_gb': plan.disk_space_gb,
            'bandwidth_gb': plan.bandwidth_gb,
            'email_accounts': plan.email_accounts,
            'databases': plan.databases,
            'domains': plan.domains,
            'cpu_cores': plan.cpu_cores,
            'ram_gb': plan.ram_gb,
            'plan_features': plan.features,
            'auto_provision': plan.auto_provision
        }
    
    def get_permissions(self, obj: Service) -> dict[str, bool]:
        """Get customer permissions for this service"""
        # For customer API, most management actions are limited
        return {
            'can_view_details': True,
            'can_view_usage': True,
            'can_change_auto_renew': True,
            'can_request_suspension': obj.status == 'active',
            'can_request_reactivation': obj.status == 'suspended',
            'can_view_billing': True,
            'can_upgrade_plan': obj.status == 'active',
            'can_cancel': obj.status in ['active', 'suspended']
        }


class ServiceSummarySerializer(serializers.Serializer):
    """Service summary statistics for customer dashboard"""
    
    total = serializers.IntegerField()
    active = serializers.IntegerField()
    suspended = serializers.IntegerField()
    pending = serializers.IntegerField()
    overdue = serializers.IntegerField()
    expiring_soon = serializers.IntegerField()  # Within 30 days
    
    # Cost information
    total_monthly_cost = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_monthly_cost_with_vat = serializers.DecimalField(max_digits=10, decimal_places=2)
    
    # Usage statistics
    total_disk_usage_gb = serializers.FloatField()
    total_bandwidth_usage_gb = serializers.FloatField()
    
    # Service type breakdown
    service_types = serializers.DictField()
    
    # Recent activity
    recent_services = ServiceListSerializer(many=True)


class ServicePlanAvailableSerializer(serializers.ModelSerializer):
    """Available service plans for customer selection"""
    
    plan_type_display = serializers.CharField(source='get_plan_type_display', read_only=True)
    
    # Price calculations
    monthly_equivalent = serializers.SerializerMethodField()
    quarterly_savings = serializers.SerializerMethodField()
    annual_savings = serializers.SerializerMethodField()
    
    # Feature summary
    feature_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = ServicePlan
        fields: ClassVar = [
            'id', 'name', 'plan_type', 'plan_type_display', 'description',
            'price_monthly', 'price_quarterly', 'price_annual', 'setup_fee',
            'monthly_equivalent', 'quarterly_savings', 'annual_savings',
            'disk_space_gb', 'bandwidth_gb', 'email_accounts', 'databases',
            'domains', 'cpu_cores', 'ram_gb', 'feature_summary',
            'is_active', 'is_public', 'sort_order'
        ]
    
    def get_monthly_equivalent(self, obj: ServicePlan) -> dict[str, Decimal]:
        """Get monthly equivalent prices for all cycles"""
        return {
            'monthly': obj.get_monthly_equivalent_price('monthly'),
            'quarterly': obj.get_monthly_equivalent_price('quarterly'),
            'annual': obj.get_monthly_equivalent_price('annual')
        }
    
    def get_quarterly_savings(self, obj: ServicePlan) -> Decimal:
        """Calculate quarterly savings compared to monthly"""
        if not obj.price_quarterly:
            return Decimal('0.00')
        
        monthly_cost_3months = obj.price_monthly * 3
        return monthly_cost_3months - obj.price_quarterly
    
    def get_annual_savings(self, obj: ServicePlan) -> Decimal:
        """Calculate annual savings compared to monthly"""
        if not obj.price_annual:
            return Decimal('0.00')
        
        monthly_cost_12months = obj.price_monthly * 12
        return monthly_cost_12months - obj.price_annual
    
    def get_feature_summary(self, obj: ServicePlan) -> list[str]:
        """Get feature summary list for display"""
        features = []
        
        if obj.disk_space_gb:
            features.append(f"{obj.disk_space_gb} GB Storage")
        if obj.bandwidth_gb:
            features.append(f"{obj.bandwidth_gb} GB Traffic")
        if obj.email_accounts:
            features.append(f"{obj.email_accounts} Email Accounts")
        if obj.databases:
            features.append(f"{obj.databases} Databases")
        if obj.domains:
            features.append(f"{obj.domains} Domains")
        if obj.cpu_cores:
            features.append(f"{obj.cpu_cores} CPU Cores")
        if obj.ram_gb:
            features.append(f"{obj.ram_gb} GB RAM")
        
        return features
