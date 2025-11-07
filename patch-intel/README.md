# 📦 Patch-Intel Module

Microsoft Patch Tuesday Data Ingestion and Parsing

---

## 🎯 Overview

The `patch-intel` module retrieves, parses, and normalizes Microsoft Patch Tuesday vulnerability data from the Security Update Guide API. It provides structured CVE information including severity ratings, CVSS scores, affected products, and exploit status.

## 📂 Module Structure

```
patch-intel/
├── src/                      # Source code
│   ├── __init__.py          # Package initialization
│   ├── fetcher.py           # Microsoft API client
│   ├── parser.py            # CVRF data parser & normalizer
│   └── cli.py               # Command-line interface
├── samples/                  # Sample data
├── patchintel.py            # Main CLI entry point
└── README.md                # This file
```

## ✨ Features

- ✅ Fetch Patch Tuesday data via Microsoft Security Update Guide API
- ✅ Parse and normalize CVRF (Common Vulnerability Reporting Framework) documents
- ✅ Extract key vulnerability attributes:
  - CVE ID, severity, CVSS scores (base & temporal)
  - Descriptions, affected products, KB articles
  - Exploit status (active exploits, likelihood)
  - Remediation details and restart requirements
- ✅ Export data in JSON and CSV formats
- ✅ Generate vulnerability statistics and summaries
- ✅ Command-line interface for easy automation

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Internet connection to access Microsoft APIs

### Installation

1. **Install dependencies:**

```bash
pip install -r ../requirements.txt
```

2. **Verify installation:**

```bash
python fetch.py --help
```

---

## 📖 Usage

### Command-Line Interface

The module provides a unified CLI with multiple commands:

```bash
# Show help
python patchintel.py --help

# Display module information
python patchintel.py info
```

#### 1. Fetch Patch Tuesday Data

Fetch data for a specific month:

```bash
python patchintel.py fetch --month 2024-11
```

**Options:**

- `--month YYYY-MM` - **Required**. Month to fetch data for (e.g., 2024-11)
- `--api-key KEY` - Optional. Microsoft API key (or set MSRC_API_KEY env var)
- `--output-dir PATH` - Output directory (default: `./samples`)
- `--format FORMAT` - Output format: `json`, `csv`, or `both` (default: `both`)
- `--verbose` - Enable verbose output

**Examples:**

```bash
# Fetch November 2024 Patch Tuesday (both JSON and CSV)
python patchintel.py fetch --month 2024-11

# Fetch October 2024, JSON only
python patchintel.py fetch --month 2024-10 --format json

# Fetch with custom output directory
python patchintel.py fetch --month 2024-09 --output-dir /path/to/data

# Fetch with API key for enhanced access
python patchintel.py fetch --month 2024-11 --api-key YOUR_API_KEY
```

#### 2. Parse and Normalize Data

Parse raw CVRF data and generate normalized output:

```bash
# Parse and show statistics only
python patchintel.py parse samples/patch_tuesday_2024_11.json --stats-only

# Parse and save normalized data
python patchintel.py parse samples/patch_tuesday_2024_11.json --output-dir normalized/

# Parse and save JSON only
python patchintel.py parse samples/patch_tuesday_2024_11.json --output-dir normalized/ --format json
```

**Options:**

- `--output-dir PATH` - Output directory for normalized data
- `--format FORMAT` - Output format: `json`, `csv`, or `both` (default: `both`)
- `--stats-only` - Only display statistics, don't save files

#### 3. Process (Fetch + Parse in One Step)

Convenience command that fetches and parses in one operation:

```bash
python patchintel.py process --month 2024-11
```

This will:
1. Fetch raw data from Microsoft API
2. Parse and normalize the data
3. Generate statistics
4. Save both raw and normalized outputs

---

## 📊 Data Schema

### Normalized Vulnerability Record

Each vulnerability is normalized into the following structure:

```json
{
  "cve_id": "CVE-2024-XXXXX",
  "title": "Vulnerability Title",
  "description": "Detailed description...",
  "faq": "Frequently asked questions...",
  
  "severity": "Critical",
  "severity_value": 4,
  "cvss_base_score": 9.8,
  "cvss_temporal_score": 8.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  
  "exploit_status": "ACTIVE",
  "exploit_status_raw": "Exploitation Detected",
  
  "impact_type": "Remote Code Execution",
  
  "affected_products": ["Windows 11", "Windows Server 2022", ...],
  "affected_product_ids": ["11929", "11930", ...],
  "affected_product_count": 15,
  
  "kb_articles": ["KB5012345", "KB5012346"],
  "superceded_by": ["5012347"],
  "restart_required": "Yes",
  
  "acknowledged_researchers": ["Researcher Name"],
  
  "release_date": "2024-11-12T00:00:00Z",
  "patch_tuesday_title": "November 2024 Security Updates",
  "parsed_timestamp": "2024-11-08T10:30:00.123456"
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier |
| `title` | string | Vulnerability title |
| `description` | string | Detailed vulnerability description |
| `severity` | string | Severity level (Critical, Important, Moderate, Low) |
| `severity_value` | int | Numeric severity (4=Critical, 3=Important, 2=Moderate, 1=Low) |
| `cvss_base_score` | float | CVSS 3.x base score (0.0-10.0) |
| `cvss_temporal_score` | float | CVSS temporal score |
| `cvss_vector` | string | CVSS vector string |
| `exploit_status` | string | Normalized exploit status (ACTIVE, HIGH_RISK, LOW_RISK, UNLIKELY, UNKNOWN) |
| `impact_type` | string | Type of impact (e.g., Remote Code Execution, Elevation of Privilege) |
| `affected_products` | array | List of affected product names |
| `affected_product_count` | int | Number of affected products |
| `kb_articles` | array | Related KB article numbers |
| `restart_required` | string | Whether restart is required (Yes/No/Maybe/Unknown) |
| `release_date` | string | Patch Tuesday release date (ISO 8601) |

---

## 🔧 API Details

### Microsoft Security Update Guide API

The module uses Microsoft's official Security Update Guide API:

**Base URL:** `https://api.msrc.microsoft.com/cvrf/v2.0`

**Endpoints:**

- `GET /updates` - List all available security updates
- `GET /cvrf/{updateId}` - Get CVRF document for specific update (format: YYYY-MMM, e.g., 2024-Nov)

**Authentication:**

- Basic access works without API key
- Enhanced access may require API key (pass via `--api-key` flag)

**Rate Limits:**

- Check Microsoft's current rate limit policy
- Recommended: Add delays between requests if fetching multiple months

---

## 📁 Output Files

### Directory Structure

```
patch-intel/
├── samples/                          # Raw and parsed data
│   ├── patch_tuesday_2024_11.json   # Raw CVRF data
│   ├── patch_tuesday_2024_11.csv    # Flattened vulnerability list
│   ├── normalized_2024_11.json      # Normalized data (full structure)
│   └── normalized_2024_11.csv       # Normalized data (CSV export)
```

### File Formats

**Raw JSON** (`patch_tuesday_YYYY_MM.json`)
- Complete CVRF document from Microsoft
- Preserves all original data and structure

**Raw CSV** (`patch_tuesday_YYYY_MM.csv`)
- Flattened vulnerability list
- Basic fields for quick review

**Normalized JSON** (`normalized_YYYY_MM.json`)
- Structured, parsed vulnerability records
- Consistent schema across all months
- Ready for risk engine ingestion

**Normalized CSV** (`normalized_YYYY_MM.csv`)
- Spreadsheet-friendly format
- Truncated arrays (first 5 products)
- Good for initial analysis in Excel

---

## 📈 Statistics and Summaries

The parser automatically generates statistics when processing data:

```
==============================================================
PATCH TUESDAY DATA SUMMARY
==============================================================

Total Vulnerabilities: 89

By Severity:
  Critical       :  15
  Important      :  58
  Moderate       :  14
  Low            :   2

By Exploit Status:
  ACTIVE         :   3
  HIGH_RISK      :   8
  LOW_RISK       :  42
  UNLIKELY       :  28
  UNKNOWN        :   8

⚠️  Vulnerabilities with Active Exploits: 3
🔴 Critical Vulnerabilities: 15

📊 Average CVSS Score: 7.2
📊 Maximum CVSS Score: 9.8

🖥️  Total Affected Products: 1,247
==============================================================
```

---

## 🛠️ Programmatic Usage

### Python API

```python
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path('patch-intel/src')))

from fetcher import MicrosoftPatchFetcher
from parser import PatchDataParser

# Fetch data
fetcher = MicrosoftPatchFetcher()
data = fetcher.fetch_patch_tuesday_data('2024-11')

# Save raw data
fetcher.save_to_json(data, 'output.json')

# Parse and normalize
parser = PatchDataParser(data)
normalized = parser.parse()

# Get statistics
stats = parser.get_statistics()
print(f"Total CVEs: {stats['total_vulnerabilities']}")
print(f"Critical: {stats['critical_count']}")

# Export to DataFrame
df = parser.to_dataframe()
print(df[['cve_id', 'severity', 'cvss_base_score']].head())

# Save normalized data
parser.save_normalized_json('normalized.json')
parser.save_normalized_csv('normalized.csv')
```

---

## 🧪 Sample Data

The `samples/` directory includes sample Patch Tuesday data for testing:

- Most recent 3 Patch Tuesdays (as available)
- Both raw and normalized formats
- Useful for development and testing without API calls

---

## ⚠️ Known Limitations

1. **API Availability:** Microsoft may change API structure; module will need updates
2. **Historical Data:** Very old Patch Tuesdays may have different CVRF structure
3. **Product Mapping:** Complex product trees may not map perfectly
4. **Rate Limits:** Fetching many months rapidly may hit rate limits

---

## 🔜 Roadmap

- [ ] Add retry logic with exponential backoff
- [ ] Support for alternative data sources (RSS feeds, CSV exports)
- [ ] Caching layer to avoid redundant API calls
- [ ] Incremental updates (only fetch new CVEs)
- [ ] Integration with National Vulnerability Database (NVD)
- [ ] Automated fetching on Patch Tuesday schedule

---

## 🐛 Troubleshooting

### "No data found for YYYY-MM"

- Check that Patch Tuesday data exists for that month
- Patch Tuesday typically occurs on the second Tuesday of each month
- Try a recent month (e.g., current or previous month)

### "Import 'requests' could not be resolved"

- Install dependencies: `pip install -r ../requirements.txt`
- Verify Python environment is activated

### "Connection timeout" or network errors

- Check internet connection
- Verify no proxy/firewall blocking Microsoft APIs
- Try increasing timeout in fetch.py

### Empty or incomplete data

- Some months may have partial releases
- Check Microsoft's Security Update Guide website to verify data exists
- Try re-fetching after a few hours

---

## 📝 Contributing

When contributing to this module:

1. Maintain backward compatibility with existing data schema
2. Add tests for new functionality
3. Update this README with new features
4. Follow existing code style and documentation standards

---

## 📄 License

Part of the PatchIntel project. See main repository LICENSE file.

---

## 🙋 Support

For issues specific to this module:
1. Check this README and troubleshooting section
2. Review sample data to understand expected formats
3. Open an issue in the main repository with "patch-intel:" prefix

---

**Module Version:** 0.1.0  
**Last Updated:** November 2024  
**Maintainer:** PatchIntel Project
