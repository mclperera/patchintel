# 🚀 Quick Start Guide - PatchIntel

Get started with PatchIntel in 5 minutes!

---

## Prerequisites

- Python 3.8+
- Internet connection

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
   ```

---

## Common Commands

### 1. Fetch Latest Patch Tuesday

```bash
# Fetch current month (November 2024)
python patchintel.py fetch --month 2024-11
```

### 2. View Statistics

```bash
# Parse and show vulnerability statistics
python patchintel.py parse samples/patch_tuesday_2024_11.json --stats-only
```

### 3. Full Process

```bash
# Fetch and parse in one command
python patchintel.py process --month 2024-11
```

---

## Sample Workflow

```bash
# 1. Fetch data for last 3 months
python patchintel.py fetch --month 2024-11
python patchintel.py fetch --month 2024-10
python patchintel.py fetch --month 2024-09

# 2. Parse and save normalized data
python patchintel.py parse samples/patch_tuesday_2024_11.json --output-dir normalized/

# 3. View the outputs
ls -lh samples/
ls -lh samples/normalized/
```

---

## Output Files

After running commands, you'll find:

```
patch-intel/
├── samples/
│   ├── patch_tuesday_2024_11.json    # Raw CVRF data
│   ├── patch_tuesday_2024_11.csv     # Flattened CVE list
│   └── normalized/
│       ├── normalized_2024_11.json   # Structured data
│       └── normalized_2024_11.csv    # CSV export
```

---

## Understanding the Output

### Statistics Summary
```
Total Vulnerabilities: 89
Critical Vulnerabilities: 15
With Active Exploits: 3
Average CVSS Score: 7.2
```

### Key Fields in Normalized Data
- `cve_id`: CVE identifier
- `severity`: Critical, Important, Moderate, Low
- `cvss_base_score`: 0.0-10.0 score
- `exploit_status`: ACTIVE, HIGH_RISK, LOW_RISK, UNLIKELY
- `affected_products`: List of impacted systems
- `kb_articles`: KB update numbers

---

## Next Steps

1. **Review the data** in your preferred tool (Excel, JSON viewer, etc.)
2. **Set up automation** to fetch monthly on Patch Tuesday
3. **Integrate with Phase 2** (Asset Mapping) when available

---

## Need Help?

- 📖 Full documentation: `patch-intel/README.md`
- 🎯 Project roadmap: `docs/PRD.md`
- 💡 Command help: `python patchintel.py COMMAND --help`

---

**Happy Patching! 🛡️**
