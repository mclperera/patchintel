# Patch Priority Rating (PPR) Framework

## A. Exploitation Status (Highest Weight)

  Exploitability                          Weight   Meaning
  --------------------------------------- -------- --------------------------
  Exploitation Detected                   +50      Immediate patch required
  Exploitation More Likely                +30      Near-term patch
  Exploitation Less Likely                +10      Routine scheduling
  Exploitation Unlikely / None Provided   0        Lowest urgency

------------------------------------------------------------------------

## B. CVSS Score Weighting

  CVSS Range   Weight
  ------------ --------
  9.0--10.0    +25
  7.0--8.9     +15
  4.0--6.9     +8
  0--3.9       0

------------------------------------------------------------------------

## C. Attack Vector

  Attack Vector     Weight
  ----------------- --------
  Network (AV:N)    +20
  Adjacent (AV:A)   +10
  Local (AV:L)      +5
  Physical (AV:P)   0

------------------------------------------------------------------------

## D. Privilege Required

  Privileges    Weight
  ------------- --------
  None (PR:N)   +20
  Low (PR:L)    +10
  High (PR:H)   0

------------------------------------------------------------------------

## E. Impact Type (Microsoft Patch Tuesday Categories)

  Impact Type                     Weight
  ------------------------------- --------
  Remote Code Execution (RCE)     +30
  Elevation of Privilege (EoP)    +20
  Security Feature Bypass (SFB)   +15
  Information Disclosure (ID)     +10
  Spoofing                        +10
  Denial of Service (DoS)         +5

------------------------------------------------------------------------

## F. Asset Exposure (Optional, Organization-Specific)

  Asset Exposure          Weight
  ----------------------- --------
  Internet-facing         +30
  Server / Domain Infra   +15
  Internal Workstation    +5
  Non-critical / Lab      0

------------------------------------------------------------------------

## Example Calculation

If a vulnerability has: - Exploitation More Likely (+30) - CVSS 9.1
(+25) - Network Vector (+20) - Low Privileges Required (+10) - RCE
impact (+30) - On an internet-facing server (+30)

**Total PPR = 145 (Critical / Patch Immediately)**

------------------------------------------------------------------------

## Interpretation Tiers

  PPR Score   Priority
  ----------- --------------------
  120+        🔴 Emergency Patch
  80--119     🟠 High Priority
  40--79      🟡 Moderate
  \<40        🟢 Low
