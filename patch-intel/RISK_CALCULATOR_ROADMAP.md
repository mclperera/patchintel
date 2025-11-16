# PatchIntel Risk Calculator - Implementation Roadmap

## Overview
Interactive risk calculator that demonstrates how CVE risk varies based on asset exposure context. This feature helps users understand that the same CVE can pose different risk levels depending on their organizational environment.

## Core Concept
**"The same Critical CVE can be P0 emergency OR P3 routine, depending on YOUR asset context."**

Users select a CVE from Patch Tuesday data, then define their asset profile to see contextualized risk assessment.

---

## Implementation Phases

### Phase 1: Basic Risk Calculator (MVP) ✅ IN PROGRESS
**Goal**: Demonstrate the core concept with simple 2-factor risk assessment

**Features**:
- CVE selection from dropdown (top 20 Critical/Exploited CVEs)
- Display CVE attributes (Severity, CVSS, Attack Vector, Privileges Required, Exploitation Status, Impact Type)
- 2 user inputs:
  - Asset Exposure (Internet-facing, Server/Internal, Workstation, Isolated/Non-critical)
  - Business Criticality (Production, Development/Test, Non-business critical)
- Risk score calculation (0-100 scale with color coding)
- Risk level display (Critical/High/Medium/Low)
- Simple explanation of why the risk is at that level
- Basic recommendation based on risk level

**Risk Calculation Logic**:
```
Base Score = CVSS Score × 10
Multipliers:
- Attack Vector × Exposure match (Network + Internet-facing = highest)
- Exploitation Status (Detected = +30%, More Likely = +15%, etc.)
- Privileges Required (None = +20%, Low = +10%, High = +0%)
- Business Criticality (Production = ×1.5, Dev = ×1.0, Non-critical = ×0.7)

Final Score = min(100, Base Score × Multipliers)
```

**Placement**: New section between CVE Explorer and Executive Summary

**Deliverables**:
- [ ] Risk calculator function with simple formula
- [ ] Streamlit UI with CVE selection dropdown
- [ ] Asset profile input widgets (radio buttons)
- [ ] Risk score visualization (progress bar with color gradient)
- [ ] Risk level badge and explanation text
- [ ] Recommendation box

**Success Criteria**: User can select any CVE, change asset profile, and see risk score update in real-time

---

### Phase 2: Enhanced Risk Assessment (Week 2)
**Goal**: Add comparison mode and more detailed risk breakdown

**Features**:
- Side-by-side scenario comparison
- Detailed risk factor breakdown (show contribution of each factor)
- Visual risk matrix chart
- Export risk assessment as PDF/CSV
- More granular exposure categories
- Affected asset count consideration

**Enhancements**:
- Show all risk factors with individual scores
- Compare 2-3 scenarios simultaneously
- Visual charts (radar chart showing risk dimensions)
- Risk trend over time (if patch applied, mitigation added, etc.)

---

### Phase 3: Asset Context Integration (Week 3)
**Goal**: Connect to existing asset ingestion module

**Features**:
- Upload asset inventory CSV
- Auto-match CVEs to affected assets
- Show aggregate risk across asset portfolio
- Asset-specific recommendations
- Bulk risk assessment for multiple CVEs

**Integration Points**:
- Use existing asset-ingestion module
- Match CVE affected_products to asset inventory
- Calculate organization-wide risk exposure

---

### Phase 4: Advanced Features (Week 4)
**Goal**: Add sophistication and enterprise features

**Features**:
- Custom risk formula editor
- Risk threshold configuration
- Historical risk tracking
- Mitigation effectiveness modeling
- Integration with PPR scoring engine
- API endpoint for programmatic access
- Scheduled risk assessments

---

## Technical Architecture

### Data Flow
```
Patch Tuesday CVE Data (CSV)
    ↓
CVE Selection (Dropdown)
    ↓
User Asset Profile Input
    ↓
Risk Calculation Engine
    ↓
Risk Score + Explanation + Recommendation
```

### Risk Formula (Phase 1)
```python
def calculate_risk(cve, asset_exposure, business_criticality):
    base_score = cve.cvss_score * 10
    
    # Attack Vector × Exposure matching
    if cve.attack_vector == "Network" and asset_exposure == "Internet-facing":
        exposure_multiplier = 2.0
    elif cve.attack_vector == "Network" and asset_exposure == "Server":
        exposure_multiplier = 1.5
    # ... more logic
    
    # Exploitation status boost
    exploitation_boost = {
        "Exploitation Detected": 1.3,
        "More Likely": 1.15,
        "Less Likely": 1.05,
        "Unlikely": 1.0
    }
    
    # Privileges boost
    privileges_boost = {
        "None": 1.2,
        "Low": 1.1,
        "High": 1.0
    }
    
    # Business criticality
    criticality_multiplier = {
        "Production": 1.5,
        "Development/Test": 1.0,
        "Non-critical": 0.7
    }
    
    risk_score = base_score * exposure_multiplier * 
                 exploitation_boost * privileges_boost * 
                 criticality_multiplier
    
    return min(100, risk_score)
```

### Risk Levels
- **90-100**: 🔥 CRITICAL - Emergency action required within 24 hours
- **70-89**: 🟠 HIGH - Urgent patching required within 7 days
- **40-69**: 🟡 MEDIUM - Patch in next maintenance window (30 days)
- **0-39**: 🟢 LOW - Patch in normal cycle (60-90 days)

---

## Success Metrics

### Phase 1
- Users can calculate risk for any CVE in < 10 seconds
- Risk score updates instantly when changing asset profile
- Clear visual distinction between risk levels

### Phase 2
- Users can compare 3 scenarios side-by-side
- Detailed breakdown helps users understand risk drivers

### Phase 3
- Automatic matching of CVEs to user's actual assets
- Aggregate risk view across entire environment

### Phase 4
- Customizable risk models for different organizations
- Automated risk reporting and tracking

---

## Design Principles

1. **Simplicity First**: Phase 1 should be dead simple - 2 inputs, clear output
2. **Educational**: Show WHY risk is high/low, not just a number
3. **Actionable**: Always provide clear recommendation
4. **Visual**: Use colors, charts, and progress bars for quick understanding
5. **Interactive**: Real-time updates as user changes inputs
6. **Contextual**: Risk should always relate to user's specific environment

---

## Development Notes

### Phase 1 Implementation Steps
1. Create risk calculation function
2. Add CVE selection dropdown (filter to Critical + Exploited for initial version)
3. Build asset profile input section
4. Implement risk score calculation
5. Design risk visualization (color-coded progress bar)
6. Add risk level determination and badge
7. Write explanation logic (why is risk at this level)
8. Add recommendation text based on risk level
9. Test with various CVE/asset combinations
10. Refine UI/UX based on testing

### Key Files
- `dashboard.py` - Main dashboard with new risk calculator section
- `risk_calculator.py` (new) - Risk calculation logic
- `RISK_CALCULATOR_ROADMAP.md` - This file

---

## Future Enhancements (Backlog)

- Machine learning to predict risk based on historical data
- Integration with SIEM/SOAR platforms
- Threat intelligence feed integration
- Custom asset tagging and grouping
- Risk heatmaps by department/business unit
- Mobile-friendly risk calculator widget
- Slack/Teams bot for quick risk queries
- Risk SLA tracking and alerting

---

Last Updated: November 16, 2025
Status: Phase 1 In Progress
