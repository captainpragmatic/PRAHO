# ===============================================================================
# CUSTOMER API SERIALIZERS 📊
# ===============================================================================

from rest_framework import serializers
from apps.customers.models import Customer


class CustomerSearchSerializer(serializers.ModelSerializer):
    """
    Serializer for customer search API results.
    Used in dropdowns and autocomplete fields.
    """
    
    text = serializers.CharField(source='get_display_name', read_only=True)
    
    class Meta:
        model = Customer
        fields = ['id', 'text', 'primary_email']
        read_only_fields = ['id', 'text', 'primary_email']


class CustomerServiceSerializer(serializers.Serializer):
    """
    Serializer for customer services API.
    Placeholder for future service management.
    """
    
    id = serializers.IntegerField()
    name = serializers.CharField()
    status = serializers.CharField()
    
    # This is a placeholder - will be replaced with actual service models
