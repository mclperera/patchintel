# Phase 2 → Phase 3 Integration Guide

How normalized asset data feeds into the Risk Engine.

## Overview

**Phase 1 (Patch-Intel):** CVE data from Microsoft Patch Tuesday  
**Phase 2 (Asset-Ingestion):** Normalized asset inventory ← YOU ARE HERE  
**Phase 3 (Risk-Engine):** Correlate CVEs with assets + calculate risk

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Patch Tuesday Data                                 │
│ ┌───────────────────────────────────────────────────────┐  │
│ │ Input: Microsoft CVRF API                             │  │
│ │ Output: Normalized CVE data                           │  │
│ │   - CVE IDs (CVE-2024-XXXXX)                          │  │
│ │   - Affected products (Windows Server 2022, etc.)     │  │
│ │   - CVSS scores (7.8, 9.8, etc.)                      │  │
│ │   - Severity levels (Critical, Important, etc.)       │  │
│ │   - Exploit status (Known, Detected, etc.)            │  │
│ └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Asset Inventory ← YOU ARE HERE                     │
│ ┌───────────────────────────────────────────────────────┐  │
│ │ Input: ServiceNow CMDB / CSV / JSON                   │  │
│ │ Output: Normalized asset data                         │  │
│ │   - Asset IDs (5f3b8e1a1b9a4c5d8e2f3a4b)             │  │
│ │   - Hostnames (DC-PROD-01, SQL-PROD-01)               │  │
│ │   - OS & Versions (Windows 2022, Windows 2019)        │  │
│ │   - Business Criticality (1-4)                        │  │
│ │   - Patch Groups (A-E)                                │  │
│ │   - Maintenance Windows                               │  │
│ └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Risk Engine (NEXT)                                 │
│ ┌───────────────────────────────────────────────────────┐  │
│ │ Correlation Logic:                                    │  │
│ │   1. Match CVE products → Asset OS/versions           │  │
│ │   2. Calculate base risk (CVSS × Criticality)         │  │
│ │   3. Apply multipliers (Exploit status, Age)          │  │
│ │   4. Prioritize by patch group & window               │  │
│ │                                                       │  │
│ │ Output: Risk-scored vulnerabilities per asset         │  │
│ │   - Asset + CVE pairs with contextual risk            │  │
│ │   - Patching priorities                               │  │
│ │   - Deployment schedules                              │  │
│ └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Phase 2 Output Schema

Your normalized assets have this structure:

```python
{
    "asset_id": "5f3b8e1a1b9a4c5d8e2f3a4b",
    "hostname": "DC-PROD-01",
    "os": "Windows",                    # ← Matches Phase 1 products
    "os_version": "2022",               # ← Matches Phase 1 versions
    "os_build": "21H2",
    "asset_type": "server",
    "ip_address": "10.10.1.10",
    "business_criticality": 1,          # ← Used in risk scoring
    "patch_group": "Group A",           # ← Used in scheduling
    "maintenance_window": "Sun 01:00-05:00",
    "owner": "John Smith",
    "department": "IT Infrastructure",
    "data_quality_score": 91,
    "source": "servicenow",
    "ingested_at": "2025-11-08T14:34:58.639"
}
```

## Phase 3 Correlation Example

### Step 1: Load Both Datasets

```python
import pandas as pd

# Phase 1 output (from patch-intel module)
cves = pd.read_csv('../patch-intel/samples/normalized_2025-Oct.csv')

# Phase 2 output (from asset-ingestion module)
assets = pd.read_csv('output/normalized_assets.csv')

print(f"CVEs: {len(cves)} vulnerabilities")
print(f"Assets: {len(assets)} systems")
```

### Step 2: Match CVEs to Assets

```python
# Example: Find all CVEs affecting Windows Server 2022 assets
win2022_assets = assets[
    (assets['os'] == 'Windows') & 
    (assets['os_version'] == '2022')
]

win2022_cves = cves[
    cves['affected_products'].str.contains('Windows Server 2022', na=False)
]

print(f"Windows Server 2022: {len(win2022_assets)} assets × {len(win2022_cves)} CVEs")
```

### Step 3: Calculate Risk Scores

```python
# Example risk calculation
for asset in win2022_assets.itertuples():
    for cve in win2022_cves.itertuples():
        # Base risk: CVSS × Asset Criticality
        base_risk = cve.cvss_score * (5 - asset.business_criticality)
        
        # Multipliers
        if 'Exploited' in cve.tags:
            base_risk *= 2.0
        if cve.severity == 'Critical':
            base_risk *= 1.5
        
        risk_score = min(base_risk, 100)
        
        print(f"{asset.hostname} + {cve.cve_id}: Risk={risk_score:.1f}")
```

### Step 4: Prioritize by Patch Group

```python
# Group by patch group and maintenance window
for group in assets['patch_group'].unique():
    group_assets = assets[assets['patch_group'] == group]
    window = group_assets.iloc[0]['maintenance_window']
    
    print(f"\nPatch Group {group} ({window}):")
    print(f"  Assets: {len(group_assets)}")
    print(f"  High-risk CVEs to deploy: ...")
```

## Key Matching Fields

Phase 2 provides these fields for Phase 3 correlation:

| Field | Purpose in Phase 3 | Example |
|-------|-------------------|---------|
| `os` | Match CVE products | Windows |
| `os_version` | Match CVE versions | 2022, 2019, 11, 10 |
| `os_build` | Precise matching | 21H2, 22H2 |
| `business_criticality` | Risk multiplier | 1-4 (1=highest) |
| `asset_type` | Asset grouping | server, laptop, desktop |
| `patch_group` | Deployment schedule | A-E |
| `maintenance_window` | Deployment timing | Sun 01:00-05:00 |

## Phase 3 Risk Scoring Formula

```python
risk_score = (
    cvss_base_score                    # From Phase 1 (0-10)
    * criticality_multiplier           # From Phase 2 (1-4 → 4-1)
    * exploit_multiplier               # Phase 1 tags (1.0-2.0)
    * age_multiplier                   # Days since disclosure (1.0-1.5)
    * exposure_multiplier              # Internet-facing? (1.0-1.3)
) * 10  # Scale to 0-100

# Cap at 100
risk_score = min(risk_score, 100)
```

## Example: End-to-End Workflow

```bash
# Phase 1: Fetch October 2025 Patch Tuesday
cd ../patch-intel
python patchintel.py fetch 2025-Oct
python patchintel.py process samples/2025-Oct.json output/cves_oct2025.csv

# Phase 2: Normalize asset inventory
cd ../asset-ingestion
python patchintel-assets.py normalize samples/servicenow_cmdb_export.csv output/assets.csv

# Phase 3: Risk correlation (NEXT TO BUILD)
cd ../risk-engine
python patchintel-risk.py correlate \
    --cves ../patch-intel/output/cves_oct2025.csv \
    --assets ../asset-ingestion/output/assets.csv \
    --output risk_scores.csv

python patchintel-risk.py prioritize risk_scores.csv --by-patch-group
```

## Data Quality Impact on Phase 3

High data quality in Phase 2 = Better risk accuracy in Phase 3:

- **Excellent (90-100):** Precise CVE matching, accurate risk scores
- **Good (75-89):** Most CVEs matched, minor gaps
- **Fair (50-74):** Some missed correlations
- **Poor (0-49):** Unreliable risk scoring

Current assets: **91/100 average** → Excellent correlation expected

## Phase 3 Expected Outputs

Based on current data:

**Input:**
- 233 CVEs (Oct 2025 Patch Tuesday)
- 25 assets (11× Win2022, 8× Win2019, 6× Win11, 2× Win10)

**Expected Output:**
- ~150-200 asset-CVE pairs (many CVEs affect multiple OS versions)
- Risk scores: 0-100 per pair
- Grouped by patch group (A-E)
- Scheduled by maintenance window

**Actionable Results:**
- "Deploy these 15 Critical patches to Patch Group A (6 servers) on Sunday 01:00-05:00"
- "Defer these 8 Low-risk patches to next cycle"
- "Emergency: CVE-2025-XXXXX has known exploits → deploy immediately"

## Next Steps to Build Phase 3

1. **Create risk-engine module**
   ```bash
   mkdir ../risk-engine
   cd ../risk-engine
   ```

2. **Build correlation logic**
   - Parse product names from Phase 1 CVEs
   - Match to Phase 2 OS/versions
   - Handle version ranges (e.g., "Windows 11 version 22H2 and later")

3. **Implement risk scoring**
   - CVSS × Criticality base
   - Exploit multipliers
   - Age-based adjustments

4. **Add prioritization**
   - Sort by risk score
   - Group by patch group
   - Consider maintenance windows

5. **Generate deployment schedules**
   - Timeline per patch group
   - Asset lists per deployment
   - Rollback plans

## Questions for Phase 3 Design

Before building the risk engine, consider:

1. **Version Matching:** How to handle "Windows 11 22H2 and later"?
2. **Missing CVSS:** 15% of CVEs lack scores - default value?
3. **Exploit Data:** Scrape CISA KEV? Check Exploit-DB?
4. **Patch Bundles:** Group related CVEs into KB packages?
5. **Testing:** Validate risk scoring with historical data?

## Ready to Proceed?

Phase 2 is complete with:
- ✅ 25 normalized assets
- ✅ 91/100 average data quality
- ✅ All critical fields populated
- ✅ Standard schema for Phase 3

**You can now:**
1. Add more assets to `samples/`
2. Test with your own ServiceNow export
3. Start building Phase 3 correlation logic
4. Design the risk scoring algorithm

---

**Next:** Build the Risk Engine (Phase 3) to correlate this asset data with CVEs from Phase 1.
