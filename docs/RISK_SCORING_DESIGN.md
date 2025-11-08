# Risk Scoring Design - PatchIntel Phase 3

## Overview

This document outlines all available **risk calculation dials** (parameters/factors) from Phases 1 & 2 that can be used to calculate contextual risk scores for vulnerability-asset pairs.

---

## Available Risk Dials

### FROM PHASE 1: CVE Characteristics (Vulnerability Side)

#### 1. CVSS Base Score (0-10)
**Source:** `cvss_score` field  
**Coverage:** 197/233 CVEs (84.5%)  
**Range:** 2.1 - 10.0  
**Average:** 7.0

**Use Case:** Primary quantitative risk metric (industry standard)

**Example:**
- CVSS 9.8 = Critical vulnerability
- CVSS 7.0 = High vulnerability
- CVSS 3.0 = Medium vulnerability

---

#### 2. Severity Classification
**Source:** `severity` field  
**Coverage:** 233/233 CVEs (100%)  
**Values:**
- Remote Code Execution: 33 CVEs (highest risk)
- Elevation of Privilege: 88 CVEs
- Information Disclosure: 28 CVEs
- Denial of Service: 11 CVEs
- Security Feature Bypass: 11 CVEs
- Spoofing: 15 CVEs
- Tampering: 1 CVE

**Use Case:** Qualitative severity assessment, categorical risk grouping

**Risk Weighting:**
```
Remote Code Execution     → 2.0x multiplier
Elevation of Privilege    → 1.5x multiplier
Information Disclosure    → 0.8x multiplier (informational)
Denial of Service         → 1.0x multiplier
Security Feature Bypass   → 1.2x multiplier
Spoofing                  → 0.9x multiplier
Tampering                 → 1.1x multiplier
```

---

#### 3. CVSS Vector String (Exploitability Metrics)
**Source:** `cvss_vector` field  
**Format:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C`

**Components We Can Parse:**

**Attack Vector (AV):**
- **Network (N):** Remotely exploitable → 1.5x multiplier
- **Adjacent (A):** Same network segment → 1.2x multiplier
- **Local (L):** Local access required → 1.0x multiplier
- **Physical (P):** Physical access required → 0.7x multiplier

**Attack Complexity (AC):**
- **Low (L):** Easy to exploit → 1.3x multiplier
- **High (H):** Complex exploitation → 1.0x multiplier

**Privileges Required (PR):**
- **None (N):** No privileges needed → 1.5x multiplier
- **Low (L):** Basic user privileges → 1.2x multiplier
- **High (H):** Admin/elevated privileges → 0.8x multiplier

**User Interaction (UI):**
- **None (N):** No user action needed → 1.3x multiplier
- **Required (R):** User must click/open → 1.0x multiplier

**Use Case:** Granular exploitability analysis - determines how easy it is to exploit

---

#### 4. Exploit Status (MOST CRITICAL DIAL)
**Source:** `impact_type` field (parsed)  
**Coverage:** 233/233 CVEs

**Categories:**
- **Exploited in Wild:** 3 CVEs (1.3%)
- **Publicly Disclosed:** 3 CVEs (1.3%)
- **Exploitation Unlikely:** 51 CVEs (21.9%)
- **Default/Unknown:** 176 CVEs (75.5%)

**Multipliers:**
```
Exploited in Wild         → 3.0x (HIGHEST PRIORITY)
Publicly Disclosed        → 2.0x (high risk, PoC available)
Exploitation Unlikely     → 0.5x (informational)
Default                   → 1.0x (standard risk)
```

**Use Case:** This is your **most important dial**. Active exploitation means immediate action required.

**Example:**
- CVE-2025-12345: Exploited=Yes → Deploy IMMEDIATELY regardless of other factors
- CVE-2025-67890: Exploitation Unlikely → Can defer to next cycle

---

#### 5. Release Date / Age
**Source:** `release_date` field  
**Coverage:** 233/233 CVEs (100%)  
**Format:** `2025-10-31T07:00:59`

**Age-Based Multipliers:**
```
0-7 days (Fresh)      → 1.5x (urgency high, limited info)
8-30 days             → 1.3x (standard window)
31-90 days            → 1.1x (patch lag accumulating)
90+ days (Old)        → 1.0x (if not patched yet, less urgent)
```

**Use Case:** Newer vulnerabilities = higher urgency (exploit development timeline)

---

### FROM PHASE 2: Asset Characteristics (Organizational Context)

#### 6. Business Criticality (SECOND MOST IMPORTANT DIAL)
**Source:** `business_criticality` field  
**Coverage:** 25/25 assets (100%)  
**Scale:** 1-4 (1 = Most Critical, 4 = Least Critical)

**Current Distribution:**
- Level 1 (Critical): 6 assets (24%) - Domain Controllers, Primary DB
- Level 2 (High): 9 assets (36%) - Production servers
- Level 3 (Medium): 9 assets (36%) - Development, Secondary systems
- Level 4 (Low): 1 asset (4%) - Test systems, End-user devices

**Multipliers:**
```
Level 1 (Critical)    → 2.0x (DC, primary database, core infra)
Level 2 (High)        → 1.5x (production servers)
Level 3 (Medium)      → 1.0x (development, secondary)
Level 4 (Low)         → 0.5x (test systems, non-critical)
```

**Use Case:** Organizational impact - breach of DC-PROD-01 (Level 1) is far worse than TEST-LAPTOP-05 (Level 4)

**This answers your question:** "Where does asset criticality come in?"
→ It's a **major multiplier** in the risk formula. Same CVE on Critical vs Low asset = 4x risk difference.

---

#### 7. Asset Type
**Source:** `asset_type` field  
**Coverage:** 25/25 assets (100%)

**Distribution:**
- Server: 17 assets (68%)
- Laptop: 6 assets (24%)
- Desktop: 2 assets (8%)

**Multipliers:**
```
Server        → 1.3x (always-on, critical services, high exposure)
Laptop        → 1.0x (mobile, intermittent connection)
Desktop       → 0.9x (typically internal, lower exposure)
```

**Use Case:** Exposure level and service criticality

---

#### 8. Operating System & Version (MATCHING ENGINE)
**Source:** `os` and `os_version` fields  
**Coverage:** 25/25 assets (100%)

**Distribution:**
- Windows Server 2022: 11 assets
- Windows Server 2019: 6 assets
- Windows 11 Pro: 6 assets
- Windows 10 Enterprise: 2 assets

**Use Case:** **CVE-to-Asset Matching Logic**

**Matching Rules:**
```python
# Example: CVE affects "Windows Server 2022"
# Match assets where:
#   - os == "Windows"
#   - os_version == "2022"
#   - OR os_version matches version range

# Complex matching:
CVE: "Windows 11 version 22H2 and later"
→ Match: Windows 11 with os_build >= 22H2
```

**This is NOT a risk multiplier - it's the correlation engine.**

---

#### 9. Patch Group & Maintenance Window
**Source:** `patch_group` and `maintenance_window` fields  
**Coverage:** 25/25 assets (100%)

**Patch Groups:**
- Group A: 6 assets (Critical systems - Sunday 01:00-05:00)
- Group B: 6 assets (Production - Sunday 03:00-05:00)
- Group C: 2 assets (Secondary - Sunday 00:00-04:00)
- Group D: 3 assets (Dev/Test)
- Group E: 8 assets (Non-critical)

**Use Case:** Deployment scheduling and prioritization

**Priority Logic:**
```
1. Calculate risk scores for all asset-CVE pairs
2. Group by patch_group
3. Within each group, sort by risk score descending
4. Schedule deployment during maintenance_window
```

**Not a risk multiplier - used for scheduling AFTER risk calculation**

---

#### 10. Location & Department
**Source:** `location` and `department` fields  
**Coverage:** 25/25 assets (100%)

**Locations:** 7 unique (Data Center 1, Data Center 2, etc.)  
**Departments:** 7 unique (IT Infrastructure, Database Services, etc.)

**Use Case:** Risk aggregation and reporting by business unit or geography

**Optional Multiplier (if needed):**
```
External/DMZ location     → 1.4x (higher exposure)
Internal-only location    → 1.0x (standard)
```

---

## Missing Dials (Future Enhancements)

### ❌ 1. Internet Exposure (Not Available)
**What it would be:** Flag indicating if asset is internet-facing  
**Where it would come from:** Network scanning, firewall rules, or manual tagging

**Impact:** 
```
Internet-facing    → 1.5x - 2.0x multiplier
Internal-only      → 1.0x multiplier
```

**Example:** SQL-PROD-01 behind firewall vs WEB-PROD-01 with public IP

---

### ❌ 2. CISA KEV (Known Exploited Vulnerabilities)
**What it would be:** Official US government catalog of actively exploited CVEs  
**Where it would come from:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Impact:** Would override Microsoft's exploit status (more authoritative)

**Integration:**
```python
# Fetch CISA KEV catalog
kev_cves = fetch_cisa_kev()

# Check if CVE is in KEV
if cve_id in kev_cves:
    exploit_multiplier = 3.5x  # Even higher than Microsoft's flag
```

---

### ❌ 3. Exploit Availability (PoC/Metasploit)
**What it would be:** Availability of public exploit code  
**Where it would come from:** 
- Exploit-DB
- Metasploit modules
- GitHub search for CVE ID
- Security research blogs

**Impact:**
```
Metasploit module exists     → 2.5x multiplier
Public PoC available         → 2.0x multiplier
No known exploits            → 1.0x multiplier
```

---

### ❌ 4. Vulnerability Chaining / Dependencies
**What it would be:** Prerequisites for exploitation  
**Example:** "CVE-2025-12345 can only be exploited if CVE-2025-11111 is also present"

**Your Question:** "Would there be any dependency with some vulnerabilities to be exploited. For example, for vulnerability to be exploited, A, B, C should happen, and do we have all three in our ecosystem?"

**Answer:** 
This data is **NOT** available in Microsoft's CVRF format. It would require:
1. Manual security research analysis
2. Vulnerability databases that track exploit chains
3. Custom logic per CVE family

**Workaround for Phase 3:**
- Assume all CVEs are independently exploitable
- Flag specific known chains manually (e.g., "Requires CVE-2024-XXXXX to be present")
- Phase 5 (GenAI) could analyze this from threat intelligence

---

### ❌ 5. Patch Compliance History
**What it would be:** `last_patched` field (exists but empty in sample data)  
**Where it would come from:** WSUS, SCCM, or endpoint management tools

**Impact:**
```python
days_unpatched = (today - last_patched).days

if days_unpatched > 90:
    multiplier = 1.3x  # Patch lag risk
elif days_unpatched > 30:
    multiplier = 1.1x
else:
    multiplier = 1.0x
```

---

### ❌ 6. Service Dependencies & Business Impact
**What it would be:** Mapping of services to assets + business process criticality  
**Example:** "DC-PROD-01 runs Active Directory → impacts 500 users"

**Where it would come from:** CMDB service mappings, business impact analysis

**Impact:** Could add 0.8x - 1.5x multiplier based on downstream impact

---

## Answering Your Specific Questions

### Q1: "Where does asset criticality come in?"
**Answer:** Asset criticality (`business_criticality` field) is a **major risk multiplier** (0.5x to 2.0x).

**Example:**
```
Same CVE (CVSS 8.0) on two assets:

Asset 1: DC-PROD-01 (Criticality = 1)
Risk = 8.0 × 2.0 (criticality) × other multipliers = HIGH

Asset 2: TEST-LAPTOP-03 (Criticality = 4)
Risk = 8.0 × 0.5 (criticality) × other multipliers = MEDIUM

Result: DC gets patched first in Group A (Sunday), laptop can wait for Group E
```

---

### Q2: "Do we know which are exploitable and which are informational?"
**Answer:** YES - from the `impact_type` field and `severity` field.

**Exploitable (High Priority):**
- `impact_type` contains "Exploited:Yes" → 3 CVEs (CRITICAL)
- `impact_type` contains "Publicly Disclosed:Yes" → 3 CVEs (HIGH)
- `severity` = "Remote Code Execution" → 33 CVEs (HIGH)
- `severity` = "Elevation of Privilege" → 88 CVEs (MEDIUM-HIGH)

**Informational (Lower Priority):**
- `impact_type` contains "Exploitation Unlikely" → 51 CVEs (LOW)
- `severity` = "Information Disclosure" → 28 CVEs (INFORMATIONAL)
- Low CVSS scores (< 4.0) → INFORMATIONAL

**Risk Scoring Reflects This:**
```python
if "Exploited:Yes" in impact_type:
    exploit_multiplier = 3.0  # Top priority
elif severity == "Information Disclosure":
    severity_multiplier = 0.8  # Lower priority
elif "Exploitation Unlikely" in impact_type:
    exploit_multiplier = 0.5  # Can defer
```

---

### Q3: "Would there be any dependency with some vulnerabilities to be exploited? For example, for vulnerability to be exploited, A, B, C should happen, and do we have all three in our ecosystem?"

**Answer:** This data is **NOT available** in Microsoft's Patch Tuesday data.

**What we DON'T have:**
- Explicit dependency chains (e.g., "CVE-A requires CVE-B to be present")
- Prerequisite conditions (e.g., "Only exploitable if SMBv1 is enabled")
- Configuration requirements (e.g., "Only affects systems with Feature X enabled")

**What we DO have (partial indicators):**
1. **CVSS Privileges Required (PR):**
   - PR:N (None) → No prerequisites, exploitable immediately
   - PR:L (Low) → Requires user account
   - PR:H (High) → Requires admin privileges (implies another vulnerability or misconfiguration)

2. **Attack Complexity (AC):**
   - AC:L (Low) → Easy to exploit, minimal conditions
   - AC:H (High) → Complex conditions required (but not specified)

3. **Scope (S):**
   - S:U (Unchanged) → Stays in same security context
   - S:C (Changed) → Can escape to other contexts (chaining indicator)

**Workaround Strategies:**

**Strategy 1: Assume Independence**
```python
# Treat all CVEs as independently exploitable
# This is conservative (may over-prioritize) but safer
for cve in cves:
    risk_score = calculate_risk(cve)
```

**Strategy 2: Manual Flagging**
```python
# Manually identify known chains from threat intel
KNOWN_CHAINS = {
    "CVE-2024-12345": ["CVE-2024-11111"],  # Requires this CVE
    "CVE-2024-67890": ["SMBv1_enabled"]    # Requires config
}

if cve_id in KNOWN_CHAINS:
    prerequisites = KNOWN_CHAINS[cve_id]
    if not all_prerequisites_met(asset, prerequisites):
        risk_score *= 0.3  # Lower priority
```

**Strategy 3: Phase 5 (GenAI) Enhancement**
```python
# Future: Use AI to analyze CVE descriptions + threat intel
# "This vulnerability can only be exploited if..."
# AI extracts prerequisites and checks asset inventory
```

**Realistic Approach for Phase 3:**
- Assume all CVEs are independently exploitable (conservative)
- Use CVSS Attack Complexity as a proxy (AC:H = harder, lower priority)
- Add manual override capability for known chains
- Document limitation for Phase 5 improvement

---

## Proposed Risk Scoring Formula

### Core Formula
```python
BASE_RISK = cvss_base_score  # 0-10

RISK_SCORE = (
    BASE_RISK
    * criticality_multiplier      # 0.5x - 2.0x (from asset)
    * exploit_multiplier          # 0.5x - 3.0x (from CVE)
    * severity_multiplier         # 0.8x - 2.0x (from CVE)
    * age_multiplier              # 1.0x - 1.5x (from CVE)
    * attack_vector_multiplier    # 0.7x - 1.5x (from CVSS vector)
    * attack_complexity_multiplier # 1.0x - 1.3x (from CVSS vector)
    * privileges_multiplier       # 0.8x - 1.5x (from CVSS vector)
    * user_interaction_multiplier # 1.0x - 1.3x (from CVSS vector)
    * asset_type_multiplier       # 0.9x - 1.3x (from asset)
) * 10  # Scale to 0-100

# Cap at 100
RISK_SCORE = min(RISK_SCORE, 100)
```

### Priority Bands
```
90-100: CRITICAL     → Deploy immediately (out-of-cycle if needed)
75-89:  HIGH         → Deploy this maintenance window
60-74:  ELEVATED     → Deploy this cycle
40-59:  MEDIUM       → Deploy next cycle
20-39:  LOW          → Monitor, defer 2-3 cycles
0-19:   INFORMATIONAL → Optional, defer indefinitely
```

---

## Example Scenarios

### Scenario 1: Exploited RCE on Domain Controller
```
CVE: CVE-2025-12345 (Windows RCE)
Asset: DC-PROD-01

BASE: 9.8 (CVSS Critical)
× 2.0 (Criticality = 1, Domain Controller)
× 3.0 (Exploited in Wild)
× 2.0 (Severity = RCE)
× 1.5 (Age = 3 days old)
× 1.5 (Attack Vector = Network)
× 1.3 (Attack Complexity = Low)
× 1.5 (Privileges Required = None)
× 1.3 (User Interaction = None)
× 1.3 (Asset Type = Server)

= 9.8 × 2.0 × 3.0 × 2.0 × 1.5 × 1.5 × 1.3 × 1.5 × 1.3 × 1.3 × 10
= 3,777.42 → Capped at 100

RESULT: CRITICAL (100/100)
ACTION: Emergency deployment, out-of-cycle
```

### Scenario 2: Informational Disclosure on Test Laptop
```
CVE: CVE-2025-67890 (Information Disclosure)
Asset: TEST-LAPTOP-05

BASE: 3.2 (CVSS Low)
× 0.5 (Criticality = 4, Test system)
× 0.5 (Exploitation Unlikely)
× 0.8 (Severity = Info Disclosure)
× 1.0 (Age = 45 days)
× 1.0 (Attack Vector = Local)
× 1.0 (Attack Complexity = High)
× 0.8 (Privileges Required = High)
× 1.0 (User Interaction = Required)
× 1.0 (Asset Type = Laptop)

= 3.2 × 0.5 × 0.5 × 0.8 × 1.0 × 1.0 × 1.0 × 0.8 × 1.0 × 1.0 × 10
= 5.12

RESULT: INFORMATIONAL (5/100)
ACTION: Defer, patch during next major cycle
```

### Scenario 3: Privilege Escalation on Production SQL Server
```
CVE: CVE-2025-11111 (Elevation of Privilege)
Asset: SQL-PROD-01

BASE: 7.8 (CVSS High)
× 2.0 (Criticality = 1, Production Database)
× 2.0 (Publicly Disclosed)
× 1.5 (Severity = EoP)
× 1.3 (Age = 14 days)
× 1.2 (Attack Vector = Adjacent)
× 1.0 (Attack Complexity = High)
× 1.2 (Privileges Required = Low)
× 1.0 (User Interaction = None)
× 1.3 (Asset Type = Server)

= 7.8 × 2.0 × 2.0 × 1.5 × 1.3 × 1.2 × 1.0 × 1.2 × 1.0 × 1.3 × 10
= 712.41 → Capped at 100

RESULT: CRITICAL (100/100)
ACTION: Deploy in next maintenance window (Group A, Sunday)
```

---

## Implementation Notes for Phase 3

### What to Build:

1. **CVE-Asset Matcher:**
   - Match CVE affected products → Asset OS/version
   - Handle version ranges ("Windows 11 22H2 and later")
   - Generate asset-CVE pairs

2. **Risk Calculator:**
   - Implement formula with all multipliers
   - Parse CVSS vector strings
   - Calculate risk scores (0-100)

3. **Prioritizer:**
   - Sort by risk score
   - Group by patch_group
   - Generate deployment schedule

4. **Configurability:**
   - Allow adjustment of multiplier weights
   - Enable/disable specific dials
   - Custom priority bands

### What to Validate:

- Test with known exploited CVEs
- Verify criticality differences
- Ensure informational CVEs score low
- Validate scheduling logic

---

## Conclusion

### We HAVE these risk dials:
✅ CVSS scores (quantitative)  
✅ Severity classifications (qualitative)  
✅ Exploit status (3 CVEs exploited, 51 unlikely)  
✅ CVSS vector details (attack complexity, privileges, etc.)  
✅ Asset criticality (1-4 scale)  
✅ Asset types (server/laptop/desktop)  
✅ Patch groups & windows (scheduling)  
✅ OS/version matching (correlation)

### We DON'T HAVE:
❌ Internet exposure flags  
❌ CISA KEV integration  
❌ Explicit vulnerability chaining/dependencies  
❌ Exploit availability (Metasploit/PoC)  
❌ Patch compliance history (field exists but empty)  
❌ Service dependency mappings

### For Phase 3:
- Use what we have (it's comprehensive!)
- Assume independence for vulnerability chains
- Build configurable risk engine
- Document limitations for Phase 5 enhancements

**The data we have is sufficient for a solid risk scoring system.** The missing pieces are "nice-to-haves" that can be added later.
