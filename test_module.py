"""
Quick test script to validate patch-intel module functionality
"""

import sys
from pathlib import Path

# Add patch-intel/src to path
sys.path.insert(0, str(Path(__file__).parent / 'patch-intel' / 'src'))

from fetcher import MicrosoftPatchFetcher
from parser import PatchDataParser


def test_api_connection():
    """Test connection to Microsoft API"""
    print("🔍 Testing Microsoft API connection...")
    
    fetcher = MicrosoftPatchFetcher()
    updates = fetcher.get_updates_list()
    
    if updates:
        print(f"✅ API connection successful!")
        print(f"   Found {len(updates)} available updates")
        print(f"   Recent updates: {updates[:5]}")
        return True
    else:
        print("❌ Failed to connect to API")
        return False


def test_data_fetch(month='2024-11'):
    """Test fetching data for a specific month"""
    print(f"\n🔍 Testing data fetch for {month}...")
    
    fetcher = MicrosoftPatchFetcher()
    data = fetcher.fetch_patch_tuesday_data(month)
    
    if data:
        print(f"✅ Data fetch successful!")
        doc_title = data.get('DocumentTitle', {}).get('Value', 'Unknown')
        print(f"   Document: {doc_title}")
        
        vuln_count = len(data.get('Vulnerability', []))
        print(f"   Vulnerabilities: {vuln_count}")
        return True
    else:
        print(f"❌ Failed to fetch data for {month}")
        return False


def test_parser():
    """Test parsing functionality with sample data"""
    print("\n🔍 Testing parser...")
    
    # Create minimal test data
    test_data = {
        'DocumentTitle': {'Value': 'Test Security Update'},
        'DocumentTracking': {
            'CurrentReleaseDate': '2024-11-01T00:00:00Z',
            'Revision': {'Number': '1.0'}
        },
        'ProductTree': {
            'FullProductName': [
                {'ProductID': '1', 'Value': 'Windows 11'}
            ]
        },
        'Vulnerability': [
            {
                'CVE': 'CVE-2024-TEST',
                'Title': {'Value': 'Test Vulnerability'},
                'Notes': [
                    {'Type': 1, 'Value': 'Test description'}
                ],
                'Threats': [
                    {'Type': 0, 'Description': {'Value': 'Critical'}},
                    {'Type': 3, 'Description': {'Value': 'Exploitation Detected'}}
                ],
                'CVSSScoreSets': [
                    {'BaseScore': 9.8, 'Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
                ],
                'ProductStatuses': [
                    {'Type': 1, 'ProductID': ['1']}
                ],
                'Remediations': []
            }
        ]
    }
    
    try:
        parser = PatchDataParser(test_data)
        results = parser.parse()
        
        if results and len(results) > 0:
            print(f"✅ Parser test successful!")
            print(f"   Parsed {len(results)} vulnerability")
            
            vuln = results[0]
            print(f"   CVE: {vuln['cve_id']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   CVSS: {vuln['cvss_base_score']}")
            print(f"   Exploit Status: {vuln['exploit_status']}")
            return True
        else:
            print("❌ Parser returned no results")
            return False
            
    except Exception as e:
        print(f"❌ Parser test failed: {e}")
        return False


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("🧪 PatchIntel Module Test Suite")
    print("=" * 60)
    
    results = {
        'API Connection': test_api_connection(),
        'Data Fetch': test_data_fetch(),
        'Parser': test_parser()
    }
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:20s}: {status}")
    
    all_passed = all(results.values())
    
    print("=" * 60)
    
    if all_passed:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check output above for details.")
        return 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)
