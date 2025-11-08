"""
Risk Scoring Configuration Loader
Handles loading and validation of YAML configuration files.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class RiskScoringConfig:
    """
    Risk scoring configuration with 6 core dials.
    Loaded from YAML file and provides easy access to multipliers.
    """
    
    def __init__(self, config_dict: Dict[str, Any]):
        """Initialize from parsed YAML dictionary."""
        self.raw_config = config_dict
        self._parse_config()
    
    def _parse_config(self):
        """Parse configuration dictionary into accessible attributes."""
        # Metadata
        self.name = self.raw_config.get('name', 'Unnamed Configuration')
        self.version = self.raw_config.get('version', '1.0')
        self.environment = self.raw_config.get('environment', 'production')
        
        # Dial 1: CVSS Base Score
        cvss_config = self.raw_config.get('cvss_base_score', {})
        self.use_cvss_as_base = cvss_config.get('use_as_base', True)
        self.missing_cvss_default = cvss_config.get('missing_score_default', 5.0)
        self.scale_factor = cvss_config.get('scale_factor', 10)
        
        # Dial 2: Business Criticality
        self.criticality_multipliers = self.raw_config.get('business_criticality_multiplier', {
            'level_1_critical': 2.0,
            'level_2_high': 1.5,
            'level_3_medium': 1.0,
            'level_4_low': 0.5
        })
        
        # Dial 3: Exploit Status
        self.exploit_multipliers = self.raw_config.get('exploit_status_multiplier', {
            'exploited_in_wild': 3.0,
            'publicly_disclosed': 2.0,
            'exploitation_unlikely': 0.5,
            'default': 1.0
        })
        
        # Dial 4: Severity Type
        self.severity_multipliers = self.raw_config.get('severity_type_multiplier', {
            'Remote Code Execution': 2.0,
            'Elevation of Privilege': 1.5,
            'Security Feature Bypass': 1.2,
            'Denial of Service': 1.0,
            'Tampering': 1.1,
            'Spoofing': 0.9,
            'Information Disclosure': 0.8
        })
        
        # Dial 5: Age Multiplier
        self.age_multipliers = self.raw_config.get('age_multiplier', {
            'days_0_to_7': 1.5,
            'days_8_to_30': 1.3,
            'days_31_to_90': 1.1,
            'days_90_plus': 1.0
        })
        
        # Dial 6: Asset Type
        self.asset_type_multipliers = self.raw_config.get('asset_type_multiplier', {
            'server': 1.3,
            'laptop': 1.0,
            'desktop': 0.9,
            'virtual_machine': 1.2,
            'container': 1.1
        })
        
        # Scoring configuration
        scoring_config = self.raw_config.get('scoring', {})
        self.cap_maximum = scoring_config.get('cap_maximum', 100)
        self.floor_minimum = scoring_config.get('floor_minimum', 0)
        
        # Priority bands
        self.priority_bands = self.raw_config.get('priority_bands', {})
        
        # Reporting options
        self.reporting = self.raw_config.get('reporting', {})
        
        # Validation options
        self.validation = self.raw_config.get('validation', {})
    
    def get_criticality_multiplier(self, level: int) -> float:
        """
        Get multiplier for business criticality level.
        
        Args:
            level: Criticality level (1-4)
            
        Returns:
            Multiplier value
        """
        mapping = {
            1: self.criticality_multipliers.get('level_1_critical', 2.0),
            2: self.criticality_multipliers.get('level_2_high', 1.5),
            3: self.criticality_multipliers.get('level_3_medium', 1.0),
            4: self.criticality_multipliers.get('level_4_low', 0.5)
        }
        return mapping.get(level, 1.0)  # Default to 1.0 if unknown
    
    def get_exploit_multiplier(self, impact_type: str) -> float:
        """
        Get multiplier based on exploit status.
        
        Args:
            impact_type: Impact type string from CVE data
            
        Returns:
            Multiplier value
        """
        if not impact_type or pd.isna(impact_type):
            return self.exploit_multipliers.get('default', 1.0)
        
        impact_lower = str(impact_type).lower()
        
        if 'exploited:yes' in impact_lower:
            return self.exploit_multipliers.get('exploited_in_wild', 3.0)
        elif 'publicly disclosed:yes' in impact_lower:
            return self.exploit_multipliers.get('publicly_disclosed', 2.0)
        elif 'exploitation unlikely' in impact_lower:
            return self.exploit_multipliers.get('exploitation_unlikely', 0.5)
        else:
            return self.exploit_multipliers.get('default', 1.0)
    
    def get_severity_multiplier(self, severity: str) -> float:
        """
        Get multiplier for severity type.
        
        Args:
            severity: Severity type string
            
        Returns:
            Multiplier value
        """
        return self.severity_multipliers.get(severity, 1.0)
    
    def get_age_multiplier(self, age_days: int) -> float:
        """
        Get multiplier based on vulnerability age in days.
        
        Args:
            age_days: Days since CVE release
            
        Returns:
            Multiplier value
        """
        if age_days <= 7:
            return self.age_multipliers.get('days_0_to_7', 1.5)
        elif age_days <= 30:
            return self.age_multipliers.get('days_8_to_30', 1.3)
        elif age_days <= 90:
            return self.age_multipliers.get('days_31_to_90', 1.1)
        else:
            return self.age_multipliers.get('days_90_plus', 1.0)
    
    def get_asset_type_multiplier(self, asset_type: str) -> float:
        """
        Get multiplier for asset type.
        
        Args:
            asset_type: Asset type string
            
        Returns:
            Multiplier value
        """
        return self.asset_type_multipliers.get(asset_type, 1.0)
    
    def get_priority_band(self, risk_score: float) -> Dict[str, Any]:
        """
        Get priority band for a given risk score.
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            Dictionary with band information
        """
        for band_name, band_config in self.priority_bands.items():
            min_score = band_config.get('min_score', 0)
            max_score = band_config.get('max_score', 100)
            
            if min_score <= risk_score <= max_score:
                return {
                    'name': band_name,
                    'label': band_config.get('label', band_name.upper()),
                    'action': band_config.get('action', 'No action defined'),
                    'sla_hours': band_config.get('sla_hours'),
                    'color': band_config.get('color', 'gray'),
                    **band_config
                }
        
        # Default if no band matches
        return {
            'name': 'unknown',
            'label': 'UNKNOWN',
            'action': 'Review manually',
            'sla_hours': None,
            'color': 'gray'
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return self.raw_config
    
    def __repr__(self) -> str:
        return f"RiskScoringConfig(name='{self.name}', version='{self.version}')"


def load_config(config_path: str) -> RiskScoringConfig:
    """
    Load risk scoring configuration from YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        RiskScoringConfig object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)
        
        return RiskScoringConfig(config_dict)
    
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML configuration: {e}")


def get_default_config() -> RiskScoringConfig:
    """
    Get default configuration (balanced settings).
    
    Returns:
        RiskScoringConfig with default values
    """
    default_config = {
        'name': 'Default Configuration',
        'version': '1.0',
        'cvss_base_score': {
            'use_as_base': True,
            'missing_score_default': 5.0,
            'scale_factor': 10
        },
        'business_criticality_multiplier': {
            'level_1_critical': 2.0,
            'level_2_high': 1.5,
            'level_3_medium': 1.0,
            'level_4_low': 0.5
        },
        'exploit_status_multiplier': {
            'exploited_in_wild': 3.0,
            'publicly_disclosed': 2.0,
            'exploitation_unlikely': 0.5,
            'default': 1.0
        },
        'severity_type_multiplier': {
            'Remote Code Execution': 2.0,
            'Elevation of Privilege': 1.5,
            'Security Feature Bypass': 1.2,
            'Denial of Service': 1.0,
            'Tampering': 1.1,
            'Spoofing': 0.9,
            'Information Disclosure': 0.8
        },
        'age_multiplier': {
            'days_0_to_7': 1.5,
            'days_8_to_30': 1.3,
            'days_31_to_90': 1.1,
            'days_90_plus': 1.0
        },
        'asset_type_multiplier': {
            'server': 1.3,
            'laptop': 1.0,
            'desktop': 0.9
        },
        'scoring': {
            'cap_maximum': 100,
            'floor_minimum': 0
        },
        'priority_bands': {
            'critical': {'min_score': 90, 'max_score': 100, 'label': 'CRITICAL'},
            'high': {'min_score': 75, 'max_score': 89, 'label': 'HIGH'},
            'elevated': {'min_score': 60, 'max_score': 74, 'label': 'ELEVATED'},
            'medium': {'min_score': 40, 'max_score': 59, 'label': 'MEDIUM'},
            'low': {'min_score': 20, 'max_score': 39, 'label': 'LOW'},
            'informational': {'min_score': 0, 'max_score': 19, 'label': 'INFORMATIONAL'}
        }
    }
    
    return RiskScoringConfig(default_config)


# Import pandas for type checking
import pandas as pd
