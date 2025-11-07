# PatchIntel 🛡️

**AI-Driven Patch Tuesday Risk Dashboard**

A modular framework that ingests Microsoft Patch Tuesday data, maps vulnerabilities to organizational assets, and calculates contextual risk with future GenAI reasoning capabilities.

---

## 🎯 Project Vision

PatchIntel is **not** a traditional vulnerability scanner. It is a **risk interpretation & decision-support engine** that transforms technical patch data into actionable insights for security leaders.

### Core Capabilities

- 🔍 **Patch Intelligence** - Fetch & parse Microsoft Patch Tuesday updates
- 🏢 **Asset Mapping** - Correlate vulnerabilities with organizational assets
- 📊 **Risk Scoring** - Quantify exposure with deterministic risk models
- 🤖 **AI Reasoning** (Future) - Generate insights and remediation guidance

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Internet connection

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/mclperera/patchintel.git
cd patchintel
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Fetch your first Patch Tuesday:**

```bash
cd patch-intel
python patchintel.py fetch --month 2024-11
```

4. **View module capabilities:**

```bash
python patchintel.py --help
python patchintel.py info
```

---

## 📦 Project Structure

```
patchintel/
├── docs/                    # Documentation
│   └── PRD.md              # Product Requirements Document
│
├── patch-intel/            # ✅ Phase 1: Patch Tuesday data ingestion
│   ├── src/               # Source code
│   │   ├── __init__.py   # Package initialization
│   │   ├── fetcher.py    # Microsoft API client
│   │   ├── parser.py     # Data normalizer
│   │   └── cli.py        # Command-line interface
│   ├── samples/          # Sample datasets
│   ├── patchintel.py     # Main CLI entry point
│   └── README.md         # Module documentation
│
├── asset-ingestion/        # 🚧 Phase 2: Asset inventory (coming soon)
├── risk-engine/            # 🚧 Phase 3: Risk calculation (coming soon)
├── dashboard/              # 🚧 Phase 4: Web UI (coming soon)
├── ai-layer/               # 🚧 Phase 5: GenAI reasoning (coming soon)
│
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

---

## 🏗️ Development Phases

### ✅ Phase 1: Patch Tuesday Data Ingestion (Current)

**Status:** Complete

Retrieve and normalize Microsoft Patch Tuesday vulnerability data.

**Features:**
- Fetch data via Microsoft Security Update Guide API
- Parse CVRF documents and extract CVE details
- Export to JSON and CSV formats
- Generate vulnerability statistics

**Usage:**
```bash
cd patch-intel
python fetch.py --month 2024-11
python parser.py samples/patch_tuesday_2024_11.json
```

📖 [Full Documentation](./patch-intel/README.md)

---

### 🚧 Phase 2: Asset Ingestion & Normalization (Coming Soon)

Ingest and standardize asset inventory data.

**Planned Features:**
- CSV asset import
- AD/Intune integration
- Data quality scoring
- Asset schema normalization

---

### 🚧 Phase 3: Rule-Based Risk Engine (Coming Soon)

Correlate vulnerabilities to assets and calculate risk scores.

**Planned Features:**
- CVE-to-asset matching
- Risk scoring algorithm
- Prioritized remediation lists
- Summary reports

---

### 🚧 Phase 4: Dashboard (Coming Soon)

Local web UI for visualization and exploration.

**Planned Features:**
- Risk heatmaps
- Asset vulnerability views
- CVE breakdown by severity
- Export capabilities

---

### 🚧 Phase 5: GenAI Reasoning Layer (Coming Soon)

Intelligent analysis and recommendations.

**Planned Features:**
- Natural language impact summaries
- Tailored remediation guidance
- Asset data enrichment
- Executive briefings

---

## 🔧 Current Module: patch-intel

### Fetch Patch Tuesday Data

```bash
cd patch-intel
python patchintel.py fetch --month 2024-11
```

### Parse and Analyze

```bash
# Show statistics only
python patchintel.py parse samples/patch_tuesday_2024_11.json --stats-only

# Parse and save normalized data
python patchintel.py parse samples/patch_tuesday_2024_11.json --output-dir normalized/
```

### Quick Process (Fetch + Parse)

```bash
python patchintel.py process --month 2024-11
```

### Output Example

```json
{
  "cve_id": "CVE-2024-43451",
  "title": "Windows NTLM Remote Code Execution Vulnerability",
  "severity": "Critical",
  "cvss_base_score": 9.8,
  "exploit_status": "ACTIVE",
  "affected_products": ["Windows 11", "Windows Server 2022"],
  "kb_articles": ["KB5012345"]
}
```

---

## 📊 Sample Output

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

⚠️  Vulnerabilities with Active Exploits: 3
🔴 Critical Vulnerabilities: 15
📊 Average CVSS Score: 7.2
==============================================================
```

---

## 🛠️ Technology Stack

- **Language:** Python 3.8+
- **Data Processing:** pandas
- **API Calls:** requests
- **CLI:** click
- **Future:** FastAPI, Streamlit (for dashboard)

---

## 📖 Documentation

- [Product Requirements Document](./docs/PRD.md) - Full project vision and roadmap
- [Patch-Intel Module](./patch-intel/README.md) - Phase 1 documentation

---

## 🤝 Contributing

We welcome contributions! This project follows a phased approach:

1. Each phase is a self-contained module
2. Modules can be used independently or together
3. Follow existing code style and documentation standards

**To contribute:**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Patch Tuesday data ingestion |
| Phase 2 | 🚧 Planned | Asset ingestion & normalization |
| Phase 3 | 🚧 Planned | Rule-based risk engine |
| Phase 4 | 🚧 Planned | Basic dashboard |
| Phase 5 | 🚧 Planned | GenAI reasoning layer |
| Phase 6 | 💭 Future | Adaptive CMDB overlay |

---

## 📝 Release History

### v0.1.0 (Current)
- ✅ Microsoft Patch Tuesday data fetching
- ✅ CVRF document parsing and normalization
- ✅ JSON and CSV export capabilities
- ✅ Vulnerability statistics generation
- ✅ CLI interface

---

## 📄 License

[Add your license here]

---

## 🙋 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Check module-specific READMEs
- Review the PRD for project context

---

## 🎓 Learn More

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/)
- [CVRF Specification](https://www.icasi.org/cvrf/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

---

**Built with ❤️ for security teams everywhere**

*Making Patch Tuesday less painful, one module at a time.*
