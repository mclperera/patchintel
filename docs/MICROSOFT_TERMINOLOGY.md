# Microsoft Patch Tuesday Terminology

## Official Field Definitions

PatchIntel uses **100% official Microsoft terminology** from the Security Update Guide (CVRF documents).

---

## Data Fields

### 1. Impact Type (formerly mislabeled as "severity")

The **vulnerability impact category** as defined by Microsoft:

| Impact Type | Description | Priority Weight |
|------------|-------------|-----------------|
| **Remote Code Execution (RCE)** | Allows attacker to execute arbitrary code | Highest (30 pts) |
| **Elevation of Privilege (EoP)** | Allows privilege escalation | High (20 pts) |
| **Security Feature Bypass (SFB)** | Bypasses security mechanisms | Medium-High (15 pts) |
| **Information Disclosure** | Exposes sensitive information | Medium (10 pts) |
| **Spoofing** | Identity impersonation | Medium (10 pts) |
| **Denial of Service (DoS)** | Disrupts availability | Low-Medium (5 pts) |
| **Tampering** | Unauthorized data modification | Medium (varies) |

**Source**: Microsoft CVRF `Threat` element with `Type=0`

---

### 2. Attack Vector (CVSS v3.1)

The **network proximity** required to exploit the vulnerability:

| Vector | Code | Description | Priority Weight |
|--------|------|-------------|-----------------|
| **Network** | N | Remotely exploitable over network | Highest (20 pts) |
| **Adjacent** | A | Requires adjacent network access | High (10 pts) |
| **Local** | L | Requires local system access | Medium (5 pts) |
| **Physical** | P | Requires physical access to device | Lowest (0 pts) |

**Source**: Microsoft CVRF `CVSSScoreSets` - parsed from CVSS vector string `AV:X`

---

### 3. Privileges Required (CVSS v3.1)

The **authentication level** needed to exploit:

| Level | Code | Description | Priority Weight |
|-------|------|-------------|-----------------|
| **None** | N | No authentication required | Highest (20 pts) |
| **Low** | L | Basic user privileges | Medium (10 pts) |
| **High** | H | Administrator privileges | Lowest (0 pts) |

**Source**: Microsoft CVRF `CVSSScoreSets` - parsed from CVSS vector string `PR:X`

---

### 4. Exploitation Status

Microsoft's **exploitation likelihood** assessment:

| Status | Description | Priority Weight |
|--------|-------------|-----------------|
| **Exploitation Detected** | Active exploitation in the wild | Critical (50 pts) |
| **Exploitation More Likely** | Higher likelihood of exploitation | High (30 pts) |
| **Exploitation Less Likely** | Lower likelihood of exploitation | Medium (10 pts) |
| **Exploitation Unlikely** | Exploitation is unlikely | Low (0 pts) |

**Source**: Microsoft CVRF `Threat` element with `Type=1`

Full string format: `"Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"`

---

### 5. Severity Rating (separate from Impact Type)

Microsoft's **overall severity assessment**:

- **Critical** - Highest severity
- **Important** - High severity  
- **Moderate** - Medium severity
- **Low** - Lowest severity

**Source**: Microsoft CVRF `Threat` element with `Type=3`

**Note**: This is separate from CVSS Base Score, though often correlated.

---

## Column Naming Convention

### Corrected Terminology (v1.1+)

| Column Name | Contains | Example Values |
|-------------|----------|----------------|
| `impact_type` | Impact category | "Remote Code Execution", "Elevation of Privilege" |
| `exploitation_details` | Full exploitation string | "Publicly Disclosed:No;Exploited:No;..." |
| `exploitation_status` | Parsed status | "exploitation_detected", "exploitation_more_likely" |
| `attack_vector` | CVSS AV value | "N", "A", "L", "P" |
| `privileges_required` | CVSS PR value | "N", "L", "H" |

### Legacy Naming (v1.0 - deprecated)

| Old Column Name | Issue | New Column Name |
|----------------|-------|-----------------|
| `severity` | Contained Impact Type, not Severity Rating | `impact_type` |
| `impact_type` | Contained exploitation details string | `exploitation_details` |

---

## Data Source

All terminology and values are extracted directly from:

**Microsoft Security Update Guide (MSUC) API**
- Format: CVRF (Common Vulnerability Reporting Framework)
- API: `https://api.msrc.microsoft.com/cvrf/v2.0/`
- Documentation: https://msrc.microsoft.com/

### CVRF Document Structure

```json
{
  "Vulnerability": [
    {
      "CVE": "CVE-2025-12345",
      "Threats": [
        {
          "Type": 0,
          "Description": {"Value": "Remote Code Execution"}
        },
        {
          "Type": 3,
          "Description": {"Value": "Critical"}
        },
        {
          "Type": 1,
          "Description": {"Value": "Publicly Disclosed:No;Exploited:No;..."}
        }
      ],
      "CVSSScoreSets": [
        {
          "BaseScore": 9.8,
          "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ]
    }
  ]
}
```

---

## Validation

✅ **All terminology verified against**:
- Microsoft CVRF documents (October 2025, November 2025)
- CVSS v3.1 Specification
- Microsoft Security Update Guide documentation

**Last Updated**: November 15, 2025  
**Version**: 1.1  
**Status**: ✅ Verified Accurate
