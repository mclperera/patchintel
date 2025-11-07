# 📘 Product Requirements Document (PRD)  
### AI-Driven Patch Tuesday Risk Dashboard

---

## 🧭 Project Vision

Build a modular framework that ingests Microsoft Patch Tuesday data, maps vulnerabilities to organizational assets, and calculates contextual risk — with a future GenAI reasoning layer to interpret and enrich results.

This is **not** a traditional vulnerability scanner. It is a **risk interpretation & decision-support engine** that turns technical patch data into meaningful insights for security leaders.

---

## ✨ Core Objectives

| Objective | Description |
|-----------|--------------|
| Patch Intelligence | Fetch & parse Microsoft Patch Tuesday updates in a normalized format |
| Asset Mapping | Ingest & standardize asset data to correlate with vulnerabilities |
| Risk Scoring | Provide a deterministic risk model to quantify exposure |
| AI Reasoning (Future) | Generate insights, narratives, and remediation decisions using GenAI |

---

## 🧱 Phased Delivery Plan

Each phase should be committed in the repo as its own module, enabling incremental value and community contribution.

---

### ✅ **Phase 1: Patch Tuesday Data Ingestion**

**Goal:** Retrieve, parse, and store Patch Tuesday CVE data.

**Requirements:**
- Fetch Patch Tuesday data via:
  - Microsoft Security Update Guide API
  - RSS or CSV feeds as fallback options
- Extract and normalize key fields:
  - CVE ID, severity, CVSS, description, product, OS version, exploit status, release date
- Store outputs in JSON & CSV formats
- CLI command:  
  ```bash
  python patch-intel/fetch.py --month YYYY-MM
  ```

**Deliverables:**
- `/patch-intel` module
- Sample dataset for 3 most recent Patch Tuesdays
- Documentation with setup steps & usage examples

---

### 📦 **Phase 2: Asset Ingestion & Normalization**

**Goal:** Ingest and normalize asset inventory data in a standard schema.

**Requirements:**
- Support at least 2 data sources:
  - CSV asset export (baseline)
  - AD/Intune export (optional stretch goal)
- Create a standardized asset schema:

```json
{
  "hostname": "",
  "os": "",
  "os_version": "",
  "criticality": "",
  "owner": "",
  "tags": [],
  "data_quality_score": 0
}
```

- Implement a **data quality score** per asset to prepare for AI inference later

**Deliverables:**
- `/asset-ingestion` module
- `normalize_assets.py`
- `assets_sample.csv`
- “How to onboard your asset data” documentation

---

### 🔥 **Phase 3: Rule-Based Risk Engine (Basic Scoring)**

**Goal:** Correlate vulnerabilities to assets and compute initial risk scores.

**Requirements:**
- Match CVEs to assets by OS + version
- Scoring formula v1:

```
risk = CVSS × Criticality Weight × Exposure Weight
```

- Generate aggregated outputs:
  - Top risky assets
  - Top CVEs by impact
  - Summary report (Markdown + JSON)

**Deliverables:**
- `/risk-engine` module
- CLI:  
  ```bash
  python risk-engine/calc_risk.py
  ```
- Output:
  - `/output/risk_report.json`
  - `/output/risk_report.md`

---

### 📊 **Phase 4: Basic Dashboard (Local Web UI)**

**Goal:** Provide a simple UI for stakeholders to visualize risk data.

**Requirements:**
- Local UI via FastAPI + basic HTML/JS or Streamlit
- Must include:
  - Overall risk score / heatmap
  - Affected assets list
  - CVE breakdown by severity & exploitability

**Deliverables:**
- `/dashboard` module
- App launch script
- Local run instructions

---

### 🧠 **Phase 5: GenAI Reasoning Layer**

**Goal:** Add intelligence, explanation, and remediation guidance.

**Requirements:**
- Summarize Patch Tuesday impact in plain language
- Provide tailored remediation suggestions based on asset profile
- Identify missing asset fields + propose inferred values (CMDB enrichment v0.1)

**Deliverables:**
- `/ai-layer` module
- Prompt templates & examples
- AI-generated reports

---

### 🤖 **Phase 6: Adaptive CMDB Overlay (Stretch Goal)**

**Goal:** Enhance asset data accuracy using heuristics + GenAI reasoning.

**Concepts:**
- Confidence-based inferred OS & criticality
- Conflict resolution across data sources
- Asset “truth layer” above CMDB

(Full spec will be defined after Phase 5.)

---

## 🚧 Non-Goals (Early Phases)

To maintain focus, the following are intentionally excluded until core value is delivered:

- Automated patch deployment
- Full CMDB bidirectional sync
- Real-time threat intel correlation
- Multi-tenant SaaS deployment

---

## 🧬 Repo Skeleton (Initial Suggested Structure)

This structure enables clear module separation and makes contributions easier.

```
/docs
  ├─ PRD.md
  ├─ architecture.md
  └─ roadmap.md

/patch-intel
  ├─ fetch.py
  ├─ parser.py
  ├─ README.md
  └─ samples/

/asset-ingestion
  ├─ normalize_assets.py
  ├─ assets_sample.csv
  ├─ README.md
  └─ validators.py

/risk-engine
  ├─ calc_risk.py
  ├─ scoring_rules.py
  ├─ README.md
  └─ output/

/dashboard
  ├─ app.py
  ├─ components/
  ├─ static/
  └─ README.md

/ai-layer
  ├─ ai_summary.py
  ├─ prompts/
  └─ README.md

/tests
  ├─ test_patch_intel.py
  ├─ test_assets.py
  ├─ test_risk_engine.py

.gitignore
requirements.txt
README.md (simple overview + getting started)
```

---

## 📍 Suggested Milestone Timeline

| Phase | Duration | Output |
|--------|------------|---------|
| Phase 1 | Week 1 | Patch data module |
| Phase 2 | Week 2 | Asset ingestion baseline |
| Phase 3 | Week 3 | Working risk engine |
| Phase 4 | Week 4 | Usable local dashboard |
| Phase 5 | Week 5–6 | AI reasoning & reporting |

---

## 🧬 Future Enhancements (Backlog Ideas)

- Exploit-in-the-wild intel integration
- Slack/Teams “CISO Patch Briefing Bot”
- SBOM ingestion for app-level risk correlation
- Cloud asset ingestion (AWS, Azure, GCP)
- Plugin marketplace for new data sources

---

**Maintainer Note:**  
Each phase should be released as a tagged version (v0.1, v0.2, etc.) to show progression and enable community contribution.
