#!/usr/bin/env python
"""
Debug script to test Virtualmin API responses for disk usage and bandwidth.
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append('/Users/claudiu/Developer/PRAHO')

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')

# Setup Django
django.setup()

from apps.provisioning.virtualmin_models import VirtualminServer, VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService

def test_api_calls():
    """Test API calls for disk usage and bandwidth data"""
    
    print("=== DEBUGGING VIRTUALMIN API RESPONSES ===\n")
    
    # Get first active server
    try:
        server = VirtualminServer.objects.filter(status='active').first()
        if not server:
            print("❌ No active Virtualmin servers found")
            return
            
        print(f"🖥️  Testing server: {server.hostname}")
        
        # Get provisioning service
        provisioning_service = VirtualminProvisioningService()
        gateway = provisioning_service._get_gateway(server)
        
        # Test with a few domains
        accounts = VirtualminAccount.objects.filter(server=server)[:3]
        
        for account in accounts:
            print(f"\n📌 Testing domain: {account.domain}")
            print(f"   Current stored values:")
            print(f"   - Disk usage: {account.current_disk_usage_mb} MB")
            print(f"   - Bandwidth usage: {account.current_bandwidth_usage_mb} MB")
            
            # Test list-domains with multiline
            print(f"\n   🔍 Testing list-domains --multiline...")
            disk_result = gateway.call("list-domains", {"domain": account.domain, "multiline": ""})
            
            if disk_result.is_ok():
                response = disk_result.unwrap()
                print(f"   ✅ list-domains success: {response.success}")
                if response.success:
                    print(f"   📊 Response data keys: {list(response.data.keys())}")
                    
                    # Parse the response
                    parsed = gateway._parse_multiline_domain_response(response.data)
                    print(f"   📈 Parsed disk usage: {parsed.get('disk_usage_mb', 'N/A')} MB")
                    print(f"   📈 Parsed disk quota: {parsed.get('disk_quota_mb', 'N/A')} MB")
                    
                    # Show raw data structure for debugging
                    print(f"   🔍 Raw response structure:")
                    if 'data' in response.data:
                        for i, item in enumerate(response.data['data'][:1]):  # Show first item
                            print(f"      Item {i}: {item.get('values', {}).keys()}")
                            values = item.get('values', {})
                            for key, val in values.items():
                                if 'size' in key.lower() or 'usage' in key.lower() or 'quota' in key.lower() or 'limit' in key.lower() or 'bandwidth' in key.lower():
                                    print(f"        {key}: {val}")
                else:
                    print(f"   ❌ list-domains failed: {response.data}")
            else:
                print(f"   ❌ list-domains error: {disk_result.unwrap_err()}")
            
            # Test list-bandwidth
            print(f"\n   🔍 Testing list-bandwidth...")
            from datetime import datetime
            current_date = datetime.now()
            start_date = current_date.replace(day=1).strftime("%Y-%m-%d")
            end_date = current_date.strftime("%Y-%m-%d")
            
            bandwidth_result = gateway.call("list-bandwidth", {
                "domain": account.domain,
                "start": start_date,
                "end": end_date
            })
            
            if bandwidth_result.is_ok():
                response = bandwidth_result.unwrap()
                print(f"   ✅ list-bandwidth success: {response.success}")
                if response.success:
                    parsed_bw = gateway._parse_bandwidth_response(response.data)
                    print(f"   📈 Parsed bandwidth usage: {parsed_bw} MB")
                    print(f"   🔍 Raw bandwidth data: {str(response.data)[:200]}...")
                else:
                    print(f"   ❌ list-bandwidth failed: {response.data}")
            else:
                print(f"   ❌ list-bandwidth error: {bandwidth_result.unwrap_err()}")
            
            # Test get_domain_info method
            print(f"\n   🔍 Testing get_domain_info...")
            domain_info_result = gateway.get_domain_info(account.domain)
            
            if domain_info_result.is_ok():
                domain_info = domain_info_result.unwrap()
                print(f"   ✅ get_domain_info success:")
                print(f"      - Disk usage: {domain_info.get('disk_usage_mb')} MB")
                print(f"      - Bandwidth usage: {domain_info.get('bandwidth_usage_mb')} MB")
                print(f"      - Disk quota: {domain_info.get('disk_quota_mb')} MB")
                print(f"      - Bandwidth quota: {domain_info.get('bandwidth_quota_mb')} MB")
            else:
                print(f"   ❌ get_domain_info error: {domain_info_result.unwrap_err()}")
            
            print(f"\n   {'='*50}")
            
    except Exception as e:
        print(f"❌ Error during API testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_api_calls()