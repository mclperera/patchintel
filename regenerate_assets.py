"""
Script to regenerate asset sample data with asset_exposure field
"""

import pandas as pd
from pathlib import Path

# Read existing normalized assets
existing_file = Path('asset-ingestion/output/normalized_assets.csv')
df = pd.read_csv(existing_file)

# Add asset_exposure column based on heuristics
def estimate_exposure(row):
    """Estimate asset exposure based on hostname, criticality, and type"""
    hostname = str(row['hostname']).upper()
    criticality = row['business_criticality']
    asset_type = str(row['asset_type']).lower()
    location = str(row['location']).lower()
    
    # Internet-facing assets (web servers, edge devices)
    if 'WEB' in hostname or 'DMZ' in hostname or 'EDGE' in hostname:
        return 'internet_facing'
    
    # Server/Domain infrastructure (DCs, SQL, critical servers)
    if any(term in hostname for term in ['DC-', 'SQL-', 'EXCH-', 'AD-']):
        return 'server_domain_infra'
    
    # Critical servers
    if criticality == 1 and 'server' in asset_type:
        return 'server_domain_infra'
    
    # Test/Dev/Lab systems
    if any(term in hostname for term in ['TEST', 'DEV', 'LAB']):
        return 'non_critical'
    
    # Laptops and desktops
    if any(term in asset_type for term in ['laptop', 'desktop']):
        return 'internal_workstation'
    
    # Other servers (Level 2-3)
    if 'server' in asset_type:
        return 'server_domain_infra'
    
    # Default
    return 'internal_workstation'

# Apply the estimation
df['asset_exposure'] = df.apply(estimate_exposure, axis=1)

# Reorder columns to place asset_exposure after business_criticality
column_order = [
    'asset_id', 'hostname', 'serial_number', 'asset_type', 
    'ip_address', 'mac_address', 'location', 'department', 'owner',
    'patch_group', 'maintenance_window', 'os', 'os_version', 'os_build',
    'business_criticality', 'asset_exposure',  # New field here
    'last_patched', 'tags', 'source', 'ingested_at', 'data_quality_score'
]

df = df[column_order]

# Save back
df.to_csv(existing_file, index=False)
print(f"✅ Regenerated {existing_file} with asset_exposure field")
print(f"   Total assets: {len(df)}")
print(f"\n📊 Asset Exposure Distribution:")
print(df['asset_exposure'].value_counts())
print(f"\n🔍 Sample records:")
print(df[['hostname', 'asset_type', 'business_criticality', 'asset_exposure']].head(10))
