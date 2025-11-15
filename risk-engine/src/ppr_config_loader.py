"""
PPR Configuration Loader
Loads and manages PPR (Patch Priority Rating) configuration from YAML.
"""

import yaml
from pathlib import Path
from typing import Dict, Optional, Any


class PPRConfig:
    """
    Loads and provides access to PPR scoring configuration.
    
    Configuration includes:
    - Exploitation status points
    - CVSS score bins and points
    - Attack vector points
    - Privileges required points
    - Impact type points
    - Asset exposure points
    - Priority bands
    - Parsing rules
    """
    
    def __init__(self, config_path: str):
        """
        Initialize PPR configuration from YAML file.
        
        Args:
            config_path: Path to PPR YAML configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # Cache frequently accessed config sections
        self.exploitation_points = self.config.get('exploitation_status_points', {})
        self.cvss_bins = self.config.get('cvss_score_points', {})
        self.attack_vector_points = self.config.get('attack_vector_points', {})
        self.privilege_points = self.config.get('privileges_required_points', {})
        self.impact_points = self.config.get('impact_type_points', {})
        self.exposure_points = self.config.get('asset_exposure_points', {})
        self.priority_bands = self.config.get('priority_bands', {})
        self.parsing_rules = self.config.get('parsing', {})
        
    def _load_config(self) -> Dict:
        """
        Load configuration from YAML file.
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"PPR configuration not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            print(f"✓ Loaded PPR configuration: {config.get('name', 'Unknown')}")
            return config
        
        except Exception as e:
            raise ValueError(f"Error loading PPR configuration: {e}")
    
    def get_exploitation_points(self, status: str) -> int:
        """
        Get points for exploitation status.
        
        Args:
            status: Exploitation status (exploitation_detected, exploitation_more_likely, etc.)
            
        Returns:
            Points for this exploitation status
        """
        return self.exploitation_points.get(status, self.exploitation_points.get('unknown', 5))
    
    def get_cvss_points(self, cvss_score: Optional[float]) -> int:
        """
        Get points for CVSS score based on bins.
        
        Args:
            cvss_score: CVSS base score (0-10), None if missing
            
        Returns:
            Points for this CVSS score
        """
        if cvss_score is None:
            return self.config.get('missing_cvss_default', 5)
        
        # Check each bin
        for bin_name, bin_config in self.cvss_bins.items():
            if isinstance(bin_config, dict):
                min_score = bin_config.get('min_score', 0)
                max_score = bin_config.get('max_score', 10)
                
                if min_score <= cvss_score <= max_score:
                    return bin_config.get('points', 0)
        
        # Default fallback
        return 0
    
    def get_attack_vector_points(self, attack_vector: str) -> int:
        """
        Get points for attack vector.
        
        Args:
            attack_vector: Attack vector code (N, A, L, P) or name (network, adjacent, etc.)
            
        Returns:
            Points for this attack vector
        """
        # Map single-letter codes to full names if needed
        av_mapping = self.parsing_rules.get('attack_vector', {}).get('mapping', {})
        
        if attack_vector in av_mapping:
            attack_vector = av_mapping[attack_vector]
        
        return self.attack_vector_points.get(attack_vector, self.attack_vector_points.get('unknown', 5))
    
    def get_privilege_points(self, privilege_required: str) -> int:
        """
        Get points for privileges required.
        
        Args:
            privilege_required: Privilege code (N, L, H) or name (none, low, high)
            
        Returns:
            Points for this privilege level
        """
        # Map single-letter codes to full names if needed
        pr_mapping = self.parsing_rules.get('privileges_required', {}).get('mapping', {})
        
        if privilege_required in pr_mapping:
            privilege_required = pr_mapping[privilege_required]
        
        return self.privilege_points.get(privilege_required, self.privilege_points.get('unknown', 10))
    
    def get_impact_type_points(self, impact_type: str) -> int:
        """
        Get points for impact type.
        
        Args:
            impact_type: Impact type (Remote Code Execution, Elevation of Privilege, etc.)
            
        Returns:
            Points for this impact type
        """
        # Map verbose names to config keys if needed
        impact_mapping = self.parsing_rules.get('impact_type', {}).get('mapping', {})
        
        if impact_type in impact_mapping:
            impact_type = impact_mapping[impact_type]
        
        # Try lowercase version
        impact_lower = impact_type.lower().replace(' ', '_')
        
        return self.impact_points.get(impact_lower, self.impact_points.get('unknown', 10))
    
    def get_exposure_points(self, exposure: str) -> int:
        """
        Get points for asset exposure.
        
        Args:
            exposure: Asset exposure category (internet_facing, server_domain_infra, etc.)
            
        Returns:
            Points for this exposure level
        """
        return self.exposure_points.get(exposure, self.exposure_points.get('unknown', 10))
    
    def get_priority_band(self, ppr_score: float) -> Dict[str, Any]:
        """
        Get priority band information for a given PPR score.
        
        Args:
            ppr_score: Calculated PPR score
            
        Returns:
            Dictionary with priority band information
        """
        for band_name, band_config in self.priority_bands.items():
            min_score = band_config.get('min_score', 0)
            max_score = band_config.get('max_score', 999)
            
            if min_score <= ppr_score <= max_score:
                return {
                    'name': band_name,
                    'label': band_config.get('label', band_name),
                    'action': band_config.get('action', ''),
                    'color': band_config.get('color', 'gray'),
                    'description': band_config.get('description', '')
                }
        
        # Default fallback
        return {
            'name': 'unknown',
            'label': 'Unknown',
            'action': 'Review manually',
            'color': 'gray',
            'description': 'Score outside defined bands'
        }
    
    def parse_exploitation_status(self, impact_type_field: str) -> str:
        """
        Parse exploitation status from impact_type field.
        
        Args:
            impact_type_field: Raw impact_type field value
                             Example: "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"
            
        Returns:
            Normalized exploitation status key
        """
        if not impact_type_field:
            return 'unknown'
        
        field_lower = str(impact_type_field).lower()
        
        # Check patterns from config
        patterns = self.parsing_rules.get('exploitation_status', {}).get('patterns', {})
        
        for status_key, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.lower() in field_lower:
                    return status_key
        
        return self.parsing_rules.get('exploitation_status', {}).get('default', 'unknown')
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get configuration metadata.
        
        Returns:
            Dictionary with config metadata
        """
        return {
            'name': self.config.get('name', 'Unknown'),
            'version': self.config.get('version', '1.0'),
            'created': self.config.get('created', ''),
            'environment': self.config.get('environment', 'production'),
            'description': self.config.get('description', ''),
            'scoring_method': self.config.get('scoring_method', 'additive')
        }
    
    def get_max_possible_score(self) -> int:
        """
        Calculate the maximum possible PPR score.
        
        Returns:
            Maximum theoretical score
        """
        max_exploitation = max(self.exploitation_points.values())
        
        max_cvss = 0
        for bin_config in self.cvss_bins.values():
            if isinstance(bin_config, dict):
                max_cvss = max(max_cvss, bin_config.get('points', 0))
        
        max_attack_vector = max(self.attack_vector_points.values())
        max_privilege = max(self.privilege_points.values())
        max_impact = max(self.impact_points.values())
        max_exposure = max(self.exposure_points.values())
        
        return max_exploitation + max_cvss + max_attack_vector + max_privilege + max_impact + max_exposure
    
    def validate(self) -> bool:
        """
        Validate configuration structure and values.
        
        Returns:
            True if valid, raises ValueError if invalid
        """
        required_sections = [
            'exploitation_status_points',
            'cvss_score_points',
            'attack_vector_points',
            'privileges_required_points',
            'impact_type_points',
            'asset_exposure_points',
            'priority_bands'
        ]
        
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate priority bands don't overlap
        bands = []
        for band_name, band_config in self.priority_bands.items():
            min_score = band_config.get('min_score')
            max_score = band_config.get('max_score')
            
            if min_score is None or max_score is None:
                raise ValueError(f"Priority band '{band_name}' missing min_score or max_score")
            
            bands.append((min_score, max_score, band_name))
        
        # Check for overlaps
        bands.sort()
        for i in range(len(bands) - 1):
            if bands[i][1] >= bands[i+1][0]:
                raise ValueError(f"Priority bands overlap: {bands[i][2]} and {bands[i+1][2]}")
        
        print(f"✓ PPR configuration validated successfully")
        print(f"  Maximum possible score: {self.get_max_possible_score()}")
        print(f"  Priority bands: {len(self.priority_bands)}")
        
        return True
    
    def print_summary(self):
        """Print a summary of the configuration."""
        metadata = self.get_metadata()
        
        print("\n" + "=" * 70)
        print(f"PPR CONFIGURATION: {metadata['name']}")
        print("=" * 70)
        print(f"Version: {metadata['version']}")
        print(f"Method: {metadata['scoring_method']}")
        print(f"Description: {metadata['description']}")
        
        print(f"\n📊 Scoring Components:")
        print(f"  Exploitation Status: 0-{max(self.exploitation_points.values())} points")
        
        max_cvss = max(bin_config.get('points', 0) for bin_config in self.cvss_bins.values() if isinstance(bin_config, dict))
        print(f"  CVSS Score: 0-{max_cvss} points")
        
        print(f"  Attack Vector: 0-{max(self.attack_vector_points.values())} points")
        print(f"  Privileges Required: 0-{max(self.privilege_points.values())} points")
        print(f"  Impact Type: 0-{max(self.impact_points.values())} points")
        print(f"  Asset Exposure: 0-{max(self.exposure_points.values())} points")
        
        print(f"\n🎯 Maximum Possible Score: {self.get_max_possible_score()}")
        
        print(f"\n🚦 Priority Bands:")
        for band_name, band_config in sorted(self.priority_bands.items(), 
                                             key=lambda x: x[1].get('min_score', 0), 
                                             reverse=True):
            label = band_config.get('label', band_name)
            min_score = band_config.get('min_score')
            max_score = band_config.get('max_score')
            print(f"  {label:30s} {min_score:3d}-{max_score:3d}")
        
        print("=" * 70 + "\n")


def load_ppr_config(config_path: str) -> PPRConfig:
    """
    Load PPR configuration from file.
    
    Args:
        config_path: Path to PPR YAML configuration
        
    Returns:
        PPRConfig instance
    """
    return PPRConfig(config_path)

