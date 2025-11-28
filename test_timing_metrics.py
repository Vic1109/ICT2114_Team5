#!/usr/bin/env python3
"""
Test script to verify report generation timing metrics feature
Run this after starting your server to test the new /api/report-metrics endpoint
"""

import requests
from requests.auth import HTTPBasicAuth
import json

# Configuration - Update these with your actual values
BASE_URL = "http://localhost:8000"
USERNAME = "admin"  # Update with your username
PASSWORD = "your_password"  # Update with your password

def test_metrics_endpoint():
    """Test the new /api/report-metrics endpoint"""
    print("🧪 Testing Report Metrics API Endpoint")
    print("=" * 60)
    
    url = f"{BASE_URL}/api/report-metrics"
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ API endpoint is working!")
            print("\n📊 Metrics Response:")
            print(json.dumps(response.json(), indent=2))
            
            # Parse and display key metrics
            metrics = response.json()
            print("\n📈 Summary:")
            print(f"  Total Reports Generated: {metrics.get('reports_generated', 0)}")
            print(f"  Average Generation Time: {metrics.get('avg_generation_time_formatted', 'N/A')}")
            print(f"  Min Time: {metrics.get('min_generation_time_formatted', 'N/A')}")
            print(f"  Max Time: {metrics.get('max_generation_time_formatted', 'N/A')}")
            print(f"  Success Rate: {metrics.get('success_rate', 'N/A')}")
            print(f"  Reports in History: {len(metrics.get('report_history', []))}")
            
        elif response.status_code == 401:
            print("❌ Authentication failed. Please check USERNAME and PASSWORD.")
        else:
            print(f"❌ Unexpected status code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server. Is it running?")
        print(f"   Trying to connect to: {BASE_URL}")
    except requests.exceptions.Timeout:
        print("❌ Request timed out")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_system_status():
    """Test that system-status endpoint still works"""
    print("\n🧪 Testing System Status (for comparison)")
    print("=" * 60)
    
    url = f"{BASE_URL}/system-status"
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ System Status endpoint working!")
            data = response.json()
            print(f"  RAG Ready: {data.get('components', {}).get('rag_ready', 'Unknown')}")
            print(f"  Charts Available: {data.get('components', {}).get('charts_available', 'Unknown')}")
        else:
            print(f"⚠️ Status code: {response.status_code}")
            
    except Exception as e:
        print(f"⚠️ Could not fetch system status: {e}")

if __name__ == "__main__":
    print("\n🚀 Report Timing Metrics Test Suite")
    print("=" * 60)
    print(f"Target Server: {BASE_URL}")
    print(f"Username: {USERNAME}")
    print("=" * 60)
    print("\n⚠️  Make sure to update USERNAME and PASSWORD in this script!")
    print()
    
    test_metrics_endpoint()
    test_system_status()
    
    print("\n" + "=" * 60)
    print("📝 Next Steps:")
    print("  1. Generate a report via the dashboard")
    print("  2. Run this script again to see timing metrics")
    print("  3. Check the console output for '⏱️ Report generated...' messages")
    print("=" * 60)
