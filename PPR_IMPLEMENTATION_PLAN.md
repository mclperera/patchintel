# Patch Priority Rating (PPR) Implementation Plan

## Branch: `feature/ppr-risk-engine`

---

## ✅ Phase 1: Data Preparation (COMPLETED)

### What Was Done:

1. **Updated CVE Parser** (`patch-intel/src/parser.py`)
   - Added CVSS vector component extraction
   - Now extracts: `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`
   - Fixed list flattening bug to handle non-string items
   - Reparsed October 2025 Patch Tuesday: **233 CVEs** with new fields

2. **Updated Asset Normalizer** (`asset-ingestion/src/normalizer.py`)
   - Added `asset_exposure` field to standard schema
   - Four exposure categories:
     - `internet_facing` - Web servers, DMZ, public-facing assets
     - `server_domain_infra` - Domain Controllers, SQL servers, critical infrastructure
     - `internal_workstation` - Laptops, desktops, internal systems
     - `non_critical` - Test, dev, lab systems
   - Added estimation heuristics based on hostname, criticality, and asset type
   - Updated 25 assets with exposure classification

3. **Data Distribution After Updates:**

   **CVE Data (October 2025):**
   - Total CVEs: 233
   - CVSS components now available: 100%
   - Attack Vector distribution:
     - Local (L): ~65%
     - Network (N): ~30%
     - Adjacent (A): ~5%

   **Asset Data:**
   - Total assets: 25
   - Asset Exposure distribution:
     - `server_domain_infra`: 11 (44%)
     - `internal_workstation`: 8 (32%)
     - `internet_facing`: 5 (20%)
     - `non_critical`: 1 (4%)

---

## 📋 Phase 2: PPR Configuration (NEXT)

### Tasks:

1. **Create PPR Configuration File** (`risk-engine/config/ppr_scoring.yaml`)
   - Replace multiplicative multipliers with additive points
   - Define scoring schema:
     ```yaml
     exploitation_status_points:
       exploitation_detected: 50
       exploitation_more_likely: 30
       exploitation_less_likely: 10
       exploitation_unlikely: 0
     
     cvss_score_points:
       critical: 25    # 9.0-10.0
       high: 15        # 7.0-8.9
       medium: 8       # 4.0-6.9
       low: 0          # 0-3.9
     
     attack_vector_points:
       network: 20     # AV:N
       adjacent: 10    # AV:A
       local: 5        # AV:L
       physical: 0     # AV:P
     
     privilege_required_points:
       none: 20        # PR:N
       low: 10         # PR:L
       high: 0         # PR:H
     
     impact_type_points:
       remote_code_execution: 30
       elevation_of_privilege: 20
       security_feature_bypass: 15
       information_disclosure: 10
       spoofing: 10
       denial_of_service: 5
     
     asset_exposure_points:
       internet_facing: 30
       server_domain_infra: 15
       internal_workstation: 5
       non_critical: 0
     ```

2. **Define Priority Bands** (0-175+ scale)
   ```yaml
   priority_bands:
     emergency_patch:
       min_score: 120
       label: "🔴 EMERGENCY PATCH"
       action: "Deploy immediately (out-of-cycle)"
       sla_hours: 24
     
     high_priority:
       min_score: 80
       label: "🟠 HIGH PRIORITY"
       action: "Deploy in next maintenance window"
       sla_hours: 168  # 1 week
     
     moderate:
       min_score: 40
       label: "🟡 MODERATE"
       action: "Deploy this patch cycle"
       sla_hours: 720  # 30 days
     
     low:
       min_score: 0
       label: "🟢 LOW"
       action: "Defer or monitor"
       sla_hours: 2160  # 90 days
   ```

---

## 📋 Phase 3: PPR Calculator (NEXT)

### Tasks:

1. **Create PPR Calculator** (`risk-engine/src/ppr_calculator.py`)
   - Implement additive scoring formula:
     ```python
     ppr_score = (
         exploitation_points +
         cvss_bin_points +
         attack_vector_points +
         privilege_points +
         impact_type_points +
         asset_exposure_points
     )
     ```
   
2. **Key Methods:**
   - `parse_exploitation_status(impact_type: str)` - Extract from "Exploited:Yes;..."
   - `get_cvss_bin_points(cvss_score: float)` - Map to 0/8/15/25
   - `get_attack_vector_points(av: str)` - Map AV:N/A/L/P to points
   - `get_privilege_points(pr: str)` - Map PR:N/L/H to points
   - `get_impact_type_points(severity: str)` - Map RCE/EoP/etc to points
   - `get_exposure_points(exposure: str)` - Map exposure category to points
   - `calculate_single_ppr(...)` - Calculate one CVE-asset pair
   - `calculate_bulk_ppr(matches_df)` - Calculate for all matches

3. **Output Schema:**
   ```python
   {
       'ppr_score': 145,
       'exploitation_points': 50,
       'cvss_points': 25,
       'attack_vector_points': 20,
       'privilege_points': 20,
       'impact_type_points': 30,
       'exposure_points': 15,
       'priority_band': 'EMERGENCY PATCH',
       'priority_action': '...',
       'priority_sla_hours': 24
   }
   ```

---

## 📋 Phase 4: Integration & Testing (NEXT)

### Tasks:

1. **Update Risk Engine CLI** (`risk-engine/src/cli.py`)
   - Add `--scoring-method` option: `multiplier` (old) vs `ppr` (new)
   - Add comparison mode
   
2. **Update Matcher** (`risk-engine/src/matcher.py`)
   - Ensure new CVE fields (attack_vector, etc.) are passed through
   - Ensure asset_exposure is included in matches

3. **Testing:**
   - Run PPR calculator on October 2025 data (233 CVEs × 25 assets)
   - Compare distribution:
     - Current: 66% CRITICAL (1,566 matches)
     - Expected PPR: ~5-10% EMERGENCY, ~20-30% HIGH, ~40-50% MODERATE
   
4. **Validation Test Cases:**
   ```
   Test 1: Exploited RCE on Internet-Facing Server
   - CVE: Exploited:Yes, CVSS 9.8, AV:N, PR:N, RCE
   - Asset: WEB-PROD-01, internet_facing
   - Expected: 50+25+20+20+30+30 = 175 (EMERGENCY)
   
   Test 2: Info Disclosure on Internal Laptop
   - CVE: Exploitation Unlikely, CVSS 4.3, AV:L, PR:L, Info Disclosure
   - Asset: LAPTOP-05, internal_workstation
   - Expected: 0+8+5+10+10+5 = 38 (LOW)
   
   Test 3: EoP on Domain Controller
   - CVE: Exploitation More Likely, CVSS 7.8, AV:L, PR:L, EoP
   - Asset: DC-PROD-01, server_domain_infra
   - Expected: 30+15+5+10+20+15 = 95 (HIGH)
   ```

---

## 📋 Phase 5: Documentation & Rollout

### Tasks:

1. **Update README.md**
   - Explain PPR framework
   - Document new configuration options
   - Add examples

2. **Create Migration Guide**
   - How to switch from multiplier to PPR
   - How to tune PPR thresholds
   - Comparison table

3. **Update Risk Engine README**
   - PPR scoring explanation
   - Configuration guide
   - Tuning scenarios

---

## 🎯 Expected Outcomes

### Before (Multiplicative):
- **Problem:** Score inflation - 66% CRITICAL
- **Formula:** `CVSS × Crit × Exploit × Severity × Age × Type × 10`
- **Max Score:** 100 (capped)
- **Distribution:** Too many false positives

### After (PPR - Additive):
- **Solution:** Linear scoring - better distribution
- **Formula:** `Exploit + CVSS_bin + AV + PR + Impact + Exposure`
- **Max Score:** 175 (175 points possible)
- **Distribution:**
  - EMERGENCY (120+): 5-10% (~50-100 matches)
  - HIGH (80-119): 20-30% (~200-300 matches)
  - MODERATE (40-79): 40-50% (~400-500 matches)
  - LOW (<40): 20-30% (~200-300 matches)

---

## 🔧 Files Modified So Far

1. ✅ `patch-intel/src/parser.py` - CVSS vector parsing
2. ✅ `asset-ingestion/src/normalizer.py` - Asset exposure field
3. ✅ `regenerate_assets.py` - Utility to update assets
4. ✅ `reparse_cves.py` - Utility to reparse CVEs
5. ✅ `asset-ingestion/output/normalized_assets.csv` - Updated with exposure
6. ✅ `patch-intel/samples/patch_tuesday_2025_10.csv` - Updated with CVSS components

---

## 🚀 Next Steps

1. **Create `ppr_scoring.yaml`** configuration
2. **Implement `ppr_calculator.py`** with additive scoring
3. **Update CLI** to support both scoring methods
4. **Test on October 2025 data** and validate distribution
5. **Document and merge** to main

---

## 💡 Key Design Decisions

1. **Additive vs Multiplicative:** Chosen additive to prevent score inflation
2. **Priority Bands:** Moved from 0-100 to 0-175+ to allow more granularity
3. **Asset Exposure:** New field essential for contextual risk (internet-facing = higher risk)
4. **Backward Compatibility:** Keep old multiplier method available during transition
5. **Estimation Heuristics:** When exposure data unavailable, estimate from hostname/type/criticality

---

## 📊 Data Readiness Summary

| Component | Status | Notes |
|-----------|--------|-------|
| CVSS Vectors | ✅ Ready | All 8 components extracted |
| Exploitation Status | ✅ Ready | Parsed from impact_type field |
| Asset Exposure | ✅ Ready | 25 assets classified |
| Impact Types | ✅ Ready | RCE, EoP, etc. from severity field |
| CVE-Asset Matching | ⏳ Pending | Need to verify new fields pass through |
| PPR Configuration | ⏳ Pending | Next task |
| PPR Calculator | ⏳ Pending | Next task |

---

**Status:** Phase 1 Complete - Ready to begin Phase 2 (PPR Configuration)

**Branch:** `feature/ppr-risk-engine`

**Last Updated:** 2025-11-15
