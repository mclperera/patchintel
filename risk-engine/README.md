# Risk Engine

**Phase 3.1: Risk Scoring with 6 Core Dials**

The Risk Engine correlates CVE data (from patch-intel) with asset inventory (from asset-ingestion) to calculate risk scores using 6 configurable multipliers.

## Features

### 🔗 CVE-Asset Correlation
- Matches CVEs to assets based on OS and version
- Handles Windows Server (2016, 2019, 2022) and Windows (10, 11)
- Title-based product matching
- Exports detailed match data

### 📊 Risk Scoring (6 Core Dials)
1. **CVSS Base Score** - Foundation (0-10)
2. **Business Criticality** - Asset importance (0.5x - 2.0x)
3. **Exploit Status** - Is it exploited? (0.5x - 3.0x) ⚠️ **Most Critical**
4. **Severity Type** - RCE vs Info Disclosure (0.8x - 2.0x)
5. **Age/Freshness** - How new is it? (1.0x - 1.5x)
6. **Asset Type** - Server vs Desktop (0.9x - 1.3x)

**Formula:** Risk = (CVSS × Criticality × Exploit × Severity × Age × AssetType) × 10, capped at 100

### 🚦 Priority Bands
- **CRITICAL** (90-100): Deploy immediately, 24h SLA
- **HIGH** (75-89): Deploy within current cycle, 72h SLA
- **ELEVATED** (60-74): Deploy within current cycle, 7 days SLA
- **MEDIUM** (40-59): Deploy in next cycle, 30 days SLA
- **LOW** (20-39): Optional deployment
- **INFORMATIONAL** (0-19): Monitor only

## Installation

No additional packages needed - uses existing venv with pandas, click, pyyaml.

## Quick Start

### 1. Calculate Risk Scores

```bash
python risk-engine/patchintel-risk.py calculate \
  --cve-data patch-intel/samples/patch_tuesday_2025_10.csv \
  --asset-data asset-ingestion/output/normalized_assets.csv \
  --config risk-engine/config/risk_scoring.yaml \
  --output risk-engine/output/risk_scores.csv
```

**Output:**
- `risk_scores.csv` - Full risk scores with all dials and priority bands
- `cve_asset_matches.csv` - CVE-to-asset correlation data

### 2. View Summary

```bash
python risk-engine/patchintel-risk.py summary \
  --scored-data risk-engine/output/risk_scores.csv
```

### 3. Show Critical Risks

```bash
python risk-engine/patchintel-risk.py critical \
  --scored-data risk-engine/output/risk_scores.csv \
  --min-score 90
```

### 4. Analyze Specific Asset

```bash
python risk-engine/patchintel-risk.py asset-risks \
  --scored-data risk-engine/output/risk_scores.csv \
  --asset-id 5f3b8e1a1b9a4c5d8e2f3a4b
```

### 5. Analyze CVE Impact

```bash
python risk-engine/patchintel-risk.py cve-impact \
  --scored-data risk-engine/output/risk_scores.csv \
  --cve-id CVE-2025-24990
```

### 6. Match Only (No Scoring)

```bash
python risk-engine/patchintel-risk.py match \
  --cve-data patch-intel/samples/patch_tuesday_2025_10.csv \
  --asset-data asset-ingestion/output/normalized_assets.csv \
  --output risk-engine/output/matches.csv
```

## Configuration

Edit `risk-engine/config/risk_scoring.yaml` to tune multipliers:

```yaml
# Example: Make exploit status more aggressive
exploit_status_multiplier:
  exploited_in_wild: 5.0      # Was 3.0
  publicly_disclosed: 3.0      # Was 2.0
  exploitation_unlikely: 0.3   # Was 0.5
  default: 1.0

# Example: Reduce criticality impact
business_criticality_multiplier:
  level_1_critical: 1.5        # Was 2.0
  level_2_high: 1.3            # Was 1.5
  level_3_medium: 1.0
  level_4_low: 0.7             # Was 0.5
```

### Preset Configurations

**Balanced** (default): Equal weight across all dials
**Security-First**: Exploit status 5.0x, criticality 2.5x
**Conservative**: Lower multipliers, fewer CRITICAL alerts

See `config/risk_scoring.yaml` for complete tuning guide with scenarios.

## Output Format

### risk_scores.csv Columns
- **Asset Info**: asset_id, hostname, os, os_version, business_criticality, asset_type
- **CVE Info**: cve_id, title, severity, cvss_score, impact_type, release_date
- **Risk Calculation**: risk_score, cvss_base, age_days
- **Multipliers**: criticality_mult, exploit_mult, severity_mult, age_mult, asset_type_mult
- **Priority**: priority_band, priority_action, priority_sla_hours

### cve_asset_matches.csv Columns
Same as above minus risk calculation columns - just the correlation data.

## Example Results

From October 2025 Patch Tuesday:
- **233 CVEs** analyzed
- **25 Assets** in inventory
- **2,375 CVE-asset matches** (95 CVEs applicable to 21 assets)
- **1,566 CRITICAL risks** (66%)
- **Risk range**: 9.83 - 100.0 (median: 100.0)

Top vulnerable asset: **DC-PROD-01** (95 CVEs, 68 critical)

## Architecture

```
risk-engine/
├── config/
│   └── risk_scoring.yaml         # Configuration with 6 dials
├── src/
│   ├── config_loader.py          # YAML config parser
│   ├── matcher.py                # CVE-asset correlation engine
│   ├── calculator.py             # Risk scoring engine
│   └── cli.py                    # Command-line interface
├── output/
│   ├── risk_scores.csv           # Final risk scores
│   └── cve_asset_matches.csv     # Correlation data
└── patchintel-risk.py            # Main entry point
```

## Matching Logic

### Windows Version Detection
- **Windows Server 2022**: Matches "Windows Server 2022" in CVE title
- **Windows Server 2019**: Matches "Windows Server 2019" in CVE title
- **Windows 11**: Matches "Windows 11" (checks version 21H2/22H2 if specified)
- **Windows 10**: Matches "Windows 10" (checks version 20H2/21H2/22H2 if specified)
- **Generic Windows**: Matches "Windows" if no specific version in title

### Match Statistics
From our test run:
- 84% of assets affected (21/25)
- 41% of CVEs applicable (95/233)
- Average 113 CVEs per affected asset

## Risk Calculation Examples

### Example 1: Critical RCE on Production Server
- CVSS: 9.8
- Criticality: Level 1 (2.0x)
- Exploit: Exploited in Wild (3.0x)
- Severity: Remote Code Execution (2.0x)
- Age: 5 days (1.5x)
- Asset Type: Server (1.3x)
- **Risk Score: 100** (capped) → **CRITICAL**

### Example 2: Info Disclosure on Laptop
- CVSS: 4.3
- Criticality: Level 4 (0.5x)
- Exploit: Unlikely (0.5x)
- Severity: Information Disclosure (0.8x)
- Age: 100 days (1.0x)
- Asset Type: Laptop (1.0x)
- **Risk Score: 8.6** → **INFORMATIONAL**

## CLI Commands Reference

| Command | Purpose | Key Options |
|---------|---------|-------------|
| `calculate` | Full risk scoring pipeline | --cve-data, --asset-data, --config, --output |
| `match` | CVE-asset correlation only | --cve-data, --asset-data, --output |
| `summary` | Statistics overview | --scored-data |
| `critical` | Critical risks above threshold | --scored-data, --min-score |
| `asset-risks` | All risks for one asset | --scored-data, --asset-id |
| `cve-impact` | All assets affected by CVE | --scored-data, --cve-id |

## Next Steps (Phase 3.2)

**8 Additional Dials (Deferred):**
1. Attack Complexity (CVSS vector)
2. Privileges Required (CVSS vector)
3. User Interaction (CVSS vector)
4. Scope (CVSS vector)
5. Confidentiality Impact (CVSS vector)
6. Integrity Impact (CVSS vector)
7. Availability Impact (CVSS vector)
8. Network Location (Asset data)

These require CVSS vector parsing and additional asset fields.

## Troubleshooting

### No matches found
- Check if asset OS values align with CVE titles
- Verify Windows version strings (e.g., "Windows 2022" not "Win2022")
- Review matcher.py OS normalization logic

### All risks showing CRITICAL
- CVSS scores too high (many 7.0+)
- Adjust multipliers in config to spread distribution
- Consider lowering exploit_status or severity_type multipliers

### Configuration not loading
- Check YAML syntax (indentation, colons)
- Ensure file exists at specified path
- Use --config with absolute path

## Documentation

- **Configuration Guide**: `config/risk_scoring.yaml` (inline comments)
- **Risk Dial Analysis**: `/docs/RISK_SCORING_DESIGN.md` (comprehensive breakdown)
- **PRD**: `/PRD(1).md` (Phase 3 requirements)

## Contributing

When adding new dials:
1. Update `risk_scoring.yaml` with new multiplier section
2. Add getter method in `config_loader.py`
3. Update calculation logic in `calculator.py`
4. Update CLI output in `cli.py`
5. Document in this README and design doc
