# 🚀 Quick Start Guide - PatchIntel

Get started with PatchIntel in 5 minutes! Both Phase 1 (CVE Data) and Phase 2 (Asset Data) are ready.

---

## Prerequisites

- Python 3.13+ (or 3.8+)
- Internet connection
- Virtual environment activated

---

## Setup

1. **Navigate to the project:**
   ```bash
   cd /path/to/patchintel
   ```

2. **Activate virtual environment:**
   ```bash
   source venv/bin/activate
   ```

3. **Verify installation:**
   ```bash
   cd patch-intel
   python patchintel.py --help
   
   cd ../asset-ingestion
   python patchintel-assets.py --help
   ```

---

## Phase 1: Patch Tuesday Data (CVEs)

### 1. Fetch Latest Patch Tuesday

```bash
cd patch-intel

# Fetch October 2025 (most recent full release)
python patchintel.py fetch 2025-Oct
```

### 2. Process and Normalize

```bash
# Process: fetch + parse + normalize in one command
python patchintel.py process 2025-Oct
```

### 3. View Statistics

```bash
# Show vulnerability breakdown
python patchintel.py info samples/2025-Oct.json
```

**Output:** 233 CVEs with CVSS scores, severity levels, and affected products.

---

## Phase 2: Asset Data (Inventory)

### 1. Preview Your Assets

```bash
cd asset-ingestion

# Load sample ServiceNow export
python patchintel-assets.py ingest samples/servicenow_cmdb_export.csv --preview
```

### 2. Normalize Asset Data

```bash
# Transform to standard schema
python patchintel-assets.py normalize samples/servicenow_cmdb_export.csv output/assets.csv --stats
```

### 3. Validate Data Quality

```bash
# Check data completeness
python patchintel-assets.py validate samples/servicenow_cmdb_export.csv --min-quality 70
```

**Output:** 25 assets normalized with 91/100 quality score, ready for Phase 3.

---

## Complete Workflow (Phases 1 + 2)

```bash
# Step 1: Get CVE data
cd patch-intel
python patchintel.py process 2025-Oct

# Step 2: Normalize assets
cd ../asset-ingestion
python patchintel-assets.py normalize samples/servicenow_cmdb_export.csv output/normalized_assets.csv

# Step 3: You now have both datasets ready for Phase 3!
# - CVEs: patch-intel/samples/normalized_2025-Oct.csv (233 vulnerabilities)
# - Assets: asset-ingestion/output/normalized_assets.csv (25 systems)
```

---

## Sample Workflow: Your Own Data

### Using Your ServiceNow Export

```bash
cd asset-ingestion

# 1. Export from ServiceNow (include: sys_id, name, operating_system, os_version, business_criticality)
# 2. Load your export
python patchintel-assets.py ingest /path/to/your_cmdb_export.csv -s servicenow --preview

# 3. Normalize
python patchintel-assets.py normalize /path/to/your_cmdb_export.csv output/your_assets.csv --stats

# 4. Validate quality
python patchintel-assets.py validate /path/to/your_cmdb_export.csv --min-quality 80
```

---

## Output Files

After running commands:

```
patchintel/
├── patch-intel/
│   └── samples/
│       ├── 2025-Oct.json              # Raw CVRF (233 CVEs)
│       └── normalized_2025-Oct.csv    # Normalized CVE data
│
└── asset-ingestion/
    └── output/
        ├── normalized_assets.csv      # Normalized assets (20 fields)
        └── normalized_assets.json     # JSON format
```

---

## Understanding the Outputs

### Phase 1: CVE Data
```csv
cve_id,title,severity,cvss_score,affected_products,exploit_status
CVE-2025-12345,Windows RCE Vuln,Critical,9.8,Windows Server 2022,Exploited
```

**Key Fields:**
- `severity`: Critical, Important, Moderate, Low
- `cvss_score`: 0.0-10.0 risk score
- `affected_products`: OS/software impacted
- `exploit_status`: Known exploitation

### Phase 2: Asset Data
```csv
asset_id,hostname,os,os_version,business_criticality,patch_group,data_quality_score
5f3b...,DC-PROD-01,Windows,2022,1,Group A,91
```

**Key Fields:**
- `os` + `os_version`: For CVE matching
- `business_criticality`: 1-4 (1=Critical)
- `patch_group`: Deployment schedule
- `data_quality_score`: 0-100 completeness

---

## Statistics at a Glance

### Phase 1 Data (Oct 2025)
- **Total CVEs:** 233
- **Critical:** 15 (6%)
- **CVSS Coverage:** 84.5% have scores
- **Exploits Known:** Check exploit_status field

### Phase 2 Data (Sample)
- **Total Assets:** 25
- **Servers:** 17 (Windows Server 2022/2019)
- **Endpoints:** 8 (Windows 11/10)
- **Avg Quality:** 91/100 (Excellent)

---

## Next Steps

1. **Phase 3 (Next):** Build Risk Engine to correlate CVEs with assets
2. **Integration:** Match 233 CVEs to 25 assets = ~150-200 risk scores
3. **Prioritization:** Generate patching schedule by patch group

---

## Need Help?

- 📖 Full README: [README.md](README.md)
- 📊 Phase 2 Summary: [asset-ingestion/PHASE2_SUMMARY.md](asset-ingestion/PHASE2_SUMMARY.md)
- 🔗 Phase 3 Guide: [asset-ingestion/PHASE3_INTEGRATION.md](asset-ingestion/PHASE3_INTEGRATION.md)
- 💡 Command help: `python patchintel.py --help` or `python patchintel-assets.py --help`

---

**Happy Patching! 🛡️**

*Phases 1 & 2 Complete - Ready for Risk Correlation*
