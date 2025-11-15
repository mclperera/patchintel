#!/usr/bin/env python3
"""
Test PPR Calculator with real CVE and asset data.
"""

import sys
from pathlib import Path

# Add risk-engine/src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'risk-engine' / 'src'))

import pandas as pd
from ppr_calculator import load_ppr_calculator


def test_ppr_calculator():
    """Test PPR calculator with October 2025 data."""
    
    print("=" * 80)
    print("PPR CALCULATOR TEST WITH REAL DATA")
    print("=" * 80)
    
    # Load calculator
    print("\n1. Loading PPR Configuration...")
    config_path = Path(__file__).parent / 'risk-engine' / 'config' / 'ppr_scoring.yaml'
    calculator = load_ppr_calculator(str(config_path))
    print(f"✓ PPR Calculator loaded with configuration from {config_path.name}")
    
    # Load CVE data
    print("\n2. Loading CVE Data...")
    cve_path = '/Users/chandimaperera/Documents/My Coding Projects/patchintel/patch-intel/samples/patch_tuesday_2025_10.csv'
    cves_df = pd.read_csv(cve_path)
    print(f"✓ Loaded {len(cves_df)} CVEs from October 2025")
    
    # Load asset data
    print("\n3. Loading Asset Data...")
    asset_path = '/Users/chandimaperera/Documents/My Coding Projects/patchintel/asset-ingestion/output/normalized_assets.json'
    assets_df = pd.read_json(asset_path)
    print(f"✓ Loaded {len(assets_df)} assets")
    
    # Create sample matches for demonstration
    print("\n4. Creating Sample CVE-Asset Matches...")
    
    # Take top 10 CVEs by CVSS score
    top_cves = cves_df.nlargest(10, 'cvss_base_score')
    
    # Take 5 assets with different exposure levels
    sample_assets = assets_df.sample(min(5, len(assets_df)), random_state=42)
    
    # Cross join to create all combinations
    matches = []
    for _, cve in top_cves.iterrows():
        for _, asset in sample_assets.iterrows():
            matches.append({
                'cve_id': cve['cve_id'],
                'title': cve['title'],
                'cvss_score': cve['cvss_base_score'],
                'impact_type': cve.get('impact_type', ''),
                'attack_vector': cve.get('attack_vector', ''),
                'privileges_required': cve.get('privileges_required', ''),
                'severity': cve.get('severity', ''),
                'asset_id': asset['asset_id'],
                'hostname': asset['hostname'],
                'asset_type': asset['asset_type'],
                'asset_exposure': asset.get('asset_exposure', 'unknown'),
                'product': cve.get('affected_products', '')
            })
    
    matches_df = pd.DataFrame(matches)
    print(f"✓ Created {len(matches_df)} sample matches (10 CVEs × {len(sample_assets)} assets)")
    
    # Calculate PPR scores
    print("\n5. Calculating PPR Scores...")
    scored_df = calculator.calculate_bulk_ppr(matches_df)
    print(f"✓ PPR scores calculated")
    
    # Display summary
    calculator.print_ppr_summary(scored_df)
    
    # Show top 10 risks in detail
    print("\n" + "=" * 80)
    print("TOP 10 HIGHEST PRIORITY RISKS (DETAILED)")
    print("=" * 80)
    
    top_10 = scored_df.head(10)
    for idx, risk in top_10.iterrows():
        print(f"\n{risk['priority_band']} | PPR Score: {risk['ppr_score']:.0f}")
        print(f"  CVE: {risk['cve_id']}")
        print(f"  Title: {risk['title'][:70]}...")
        print(f"  Asset: {risk['hostname']} ({risk['asset_type']}) - {risk['asset_exposure']}")
        print(f"  CVSS: {risk['cvss_score']:.1f} | Attack Vector: {risk['attack_vector']} | Privileges: {risk['privileges_required']}")
        print(f"  Score Breakdown:")
        print(f"    Exploitation: {risk['exploitation_points']:2.0f} | CVSS: {risk['cvss_points']:2.0f} | Attack Vector: {risk['attack_vector_points']:2.0f}")
        print(f"    Privileges  : {risk['privilege_points']:2.0f} | Impact: {risk['impact_type_points']:2.0f} | Exposure: {risk['exposure_points']:2.0f}")
    
    # Test individual calculation
    print("\n" + "=" * 80)
    print("SINGLE CALCULATION TEST")
    print("=" * 80)
    
    test_cases = [
        {
            'name': 'Maximum Risk',
            'cvss_score': 9.8,
            'impact_type_field': 'Exploitation Detected - Remote Code Execution',
            'attack_vector': 'Network',
            'privileges_required': 'None',
            'severity': 'Remote Code Execution',
            'asset_exposure': 'internet_facing'
        },
        {
            'name': 'Medium Risk',
            'cvss_score': 6.5,
            'impact_type_field': 'Exploitation More Likely - Information Disclosure',
            'attack_vector': 'Adjacent Network',
            'privileges_required': 'Low',
            'severity': 'Information Disclosure',
            'asset_exposure': 'dmz'
        },
        {
            'name': 'Low Risk',
            'cvss_score': 3.2,
            'impact_type_field': 'Exploitation Less Likely - Denial of Service',
            'attack_vector': 'Local',
            'privileges_required': 'High',
            'severity': 'Denial of Service',
            'asset_exposure': 'internal'
        }
    ]
    
    for test in test_cases:
        result = calculator.calculate_single_ppr(
            cvss_score=test['cvss_score'],
            impact_type_field=test['impact_type_field'],
            attack_vector=test['attack_vector'],
            privileges_required=test['privileges_required'],
            severity=test['severity'],
            asset_exposure=test['asset_exposure']
        )
        
        print(f"\n{test['name']}:")
        print(f"  PPR Score: {result['ppr_score']:.0f} | {result['priority_band']}")
        print(f"  Components: Exploit={result['exploitation_points']} CVSS={result['cvss_points']} " +
              f"AV={result['attack_vector_points']} PR={result['privilege_points']} " +
              f"Impact={result['impact_type_points']} Exposure={result['exposure_points']}")
    
    # Export results
    print("\n" + "=" * 80)
    print("EXPORT RESULTS")
    print("=" * 80)
    
    output_path = Path(__file__).parent / 'risk-engine' / 'output' / 'ppr_test_scores.csv'
    calculator.export_scored_risks(scored_df, str(output_path))
    
    # Test filtering methods
    print("\n6. Testing Filter Methods...")
    
    emergency_risks = calculator.get_critical_risks(scored_df, min_score=120)
    print(f"✓ Emergency risks (PPR ≥ 120): {len(emergency_risks)}")
    
    high_risks = calculator.get_critical_risks(scored_df, min_score=80)
    print(f"✓ High priority risks (PPR ≥ 80): {len(high_risks)}")
    
    if len(scored_df) > 0:
        sample_asset = scored_df.iloc[0]['asset_id']
        asset_risks = calculator.get_risks_by_asset(scored_df, sample_asset)
        print(f"✓ Risks for asset {sample_asset}: {len(asset_risks)}")
        
        sample_cve = scored_df.iloc[0]['cve_id']
        cve_risks = calculator.get_risks_by_cve(scored_df, sample_cve)
        print(f"✓ Assets affected by {sample_cve}: {len(cve_risks)}")
    
    print("\n" + "=" * 80)
    print("✓ ALL TESTS COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == '__main__':
    test_ppr_calculator()
