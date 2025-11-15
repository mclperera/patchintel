"""
Script to reparse CVE data with updated parser that includes CVSS vector components
"""

import sys
import json
from pathlib import Path

# Add patch-intel/src to path
sys.path.insert(0, str(Path(__file__).parent / 'patch-intel' / 'src'))

from parser import PatchDataParser

# Files to reparse
json_files = [
    'patch-intel/samples/patch_tuesday_2025_10.json',
    'patch-intel/samples/patch_tuesday_2025_11.json',
]

for json_file in json_files:
    json_path = Path(json_file)
    
    if not json_path.exists():
        print(f"⚠️  Skipping {json_file} (not found)")
        continue
    
    print(f"\n🔄 Reparsing {json_file}...")
    
    # Load raw data
    with open(json_path, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)
    
    # Parse with updated parser
    parser = PatchDataParser(raw_data)
    normalized = parser.parse()
    
    # Save to CSV
    csv_path = json_path.with_suffix('.csv')
    parser.save_normalized_csv(str(csv_path))
    
    # Show sample with new fields
    if normalized:
        sample = normalized[0]
        print(f"\n   ✅ Reparsed {len(normalized)} CVEs")
        print(f"   📊 New CVSS component fields:")
        print(f"      Attack Vector: {sample.get('attack_vector', 'N/A')}")
        print(f"      Attack Complexity: {sample.get('attack_complexity', 'N/A')}")
        print(f"      Privileges Required: {sample.get('privileges_required', 'N/A')}")
        print(f"      User Interaction: {sample.get('user_interaction', 'N/A')}")

print("\n✅ Done! CVE data reparsed with CVSS vector components.")
