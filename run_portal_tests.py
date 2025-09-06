#!/usr/bin/env python3
"""
🧪 Portal Test Runner

Quick test runner for Portal HMAC authentication tests.
"""

import subprocess
import sys
import os

def run_tests():
    """Run Portal HMAC authentication tests"""
    
    print("🔐 Portal HMAC Authentication Tests")
    print("=" * 50)
    
    # Change to portal directory
    portal_dir = "/Users/claudiu/Developer/PRAHO/services/portal"
    os.chdir(portal_dir)
    
    # Activate virtual environment and run tests
    cmd = [
        "bash", "-c", 
        "source /Users/claudiu/Developer/PRAHO/.venv/bin/activate && "
        "python manage.py test tests.users.test_api_client_hmac -v 2"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print("📊 TEST OUTPUT:")
        print("-" * 30)
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ STDERR:")
            print("-" * 30)
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n✅ All tests passed!")
            return True
        else:
            print(f"\n❌ Tests failed with exit code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"🔥 Error running tests: {e}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
