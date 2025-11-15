"""
Test script for PPR configuration loader
"""

import sys
from pathlib import Path

# Add risk-engine/src to path
sys.path.insert(0, str(Path(__file__).parent / 'risk-engine' / 'src'))

from ppr_config_loader import load_ppr_config

# Load configuration
config_path = 'risk-engine/config/ppr_scoring.yaml'
config = load_ppr_config(config_path)

# Validate configuration
config.validate()

# Print summary
config.print_summary()

# Test component scoring
print("\n" + "=" * 70)
print("COMPONENT SCORING TESTS")
print("=" * 70)

print("\n1. Exploitation Status:")
print(f"   exploitation_detected: {config.get_exploitation_points('exploitation_detected')} points")
print(f"   exploitation_more_likely: {config.get_exploitation_points('exploitation_more_likely')} points")
print(f"   exploitation_unlikely: {config.get_exploitation_points('exploitation_unlikely')} points")

print("\n2. CVSS Score:")
print(f"   CVSS 9.8: {config.get_cvss_points(9.8)} points")
print(f"   CVSS 7.5: {config.get_cvss_points(7.5)} points")
print(f"   CVSS 5.0: {config.get_cvss_points(5.0)} points")
print(f"   CVSS 2.1: {config.get_cvss_points(2.1)} points")

print("\n3. Attack Vector:")
print(f"   Network (N): {config.get_attack_vector_points('N')} points")
print(f"   Adjacent (A): {config.get_attack_vector_points('A')} points")
print(f"   Local (L): {config.get_attack_vector_points('L')} points")

print("\n4. Privileges Required:")
print(f"   None (N): {config.get_privilege_points('N')} points")
print(f"   Low (L): {config.get_privilege_points('L')} points")
print(f"   High (H): {config.get_privilege_points('H')} points")

print("\n5. Impact Type:")
print(f"   RCE: {config.get_impact_type_points('Remote Code Execution')} points")
print(f"   EoP: {config.get_impact_type_points('Elevation of Privilege')} points")
print(f"   Info Disclosure: {config.get_impact_type_points('Information Disclosure')} points")

print("\n6. Asset Exposure:")
print(f"   internet_facing: {config.get_exposure_points('internet_facing')} points")
print(f"   server_domain_infra: {config.get_exposure_points('server_domain_infra')} points")
print(f"   internal_workstation: {config.get_exposure_points('internal_workstation')} points")

# Test parsing
print("\n" + "=" * 70)
print("PARSING TESTS")
print("=" * 70)

test_impact_type = "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"
parsed_status = config.parse_exploitation_status(test_impact_type)
print(f"\nInput: {test_impact_type}")
print(f"Parsed: {parsed_status}")
print(f"Points: {config.get_exploitation_points(parsed_status)}")

# Test priority bands
print("\n" + "=" * 70)
print("PRIORITY BAND TESTS")
print("=" * 70)

test_scores = [175, 145, 95, 65, 35, 15]
for score in test_scores:
    band = config.get_priority_band(score)
    print(f"\nScore {score}: {band['label']}")
    print(f"  Action: {band['action']}")

# Calculate example scenarios
print("\n" + "=" * 70)
print("SCENARIO CALCULATIONS")
print("=" * 70)

print("\nScenario 1: Maximum Risk (Exploited RCE on Internet-Facing Server)")
scenario1 = (
    config.get_exploitation_points('exploitation_detected') +
    config.get_cvss_points(10.0) +
    config.get_attack_vector_points('N') +
    config.get_privilege_points('N') +
    config.get_impact_type_points('Remote Code Execution') +
    config.get_exposure_points('internet_facing')
)
band1 = config.get_priority_band(scenario1)
print(f"  PPR Score: {scenario1}")
print(f"  Priority: {band1['label']}")

print("\nScenario 2: Moderate Risk (EoP on DC with Public Exploit)")
scenario2 = (
    config.get_exploitation_points('exploitation_more_likely') +
    config.get_cvss_points(7.8) +
    config.get_attack_vector_points('L') +
    config.get_privilege_points('L') +
    config.get_impact_type_points('Elevation of Privilege') +
    config.get_exposure_points('server_domain_infra')
)
band2 = config.get_priority_band(scenario2)
print(f"  PPR Score: {scenario2}")
print(f"  Priority: {band2['label']}")

print("\nScenario 3: Low Risk (Info Disclosure on Test System)")
scenario3 = (
    config.get_exploitation_points('exploitation_unlikely') +
    config.get_cvss_points(4.3) +
    config.get_attack_vector_points('L') +
    config.get_privilege_points('L') +
    config.get_impact_type_points('Information Disclosure') +
    config.get_exposure_points('non_critical')
)
band3 = config.get_priority_band(scenario3)
print(f"  PPR Score: {scenario3}")
print(f"  Priority: {band3['label']}")

print("\n" + "=" * 70)
print("✅ PPR Configuration Test Complete")
print("=" * 70)
