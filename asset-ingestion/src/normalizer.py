"""
Asset Normalization Module
Transforms raw asset data into a standardized schema for downstream processing.
"""

import pandas as pd
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class AssetNormalizer:
    """
    Normalizes asset data from various sources into a standard schema.
    
    Standard Schema:
        - asset_id: Unique identifier
        - hostname: Asset hostname/name
        - os: Operating system (normalized)
        - os_version: OS version (normalized)
        - os_build: OS build number (if available)
        - asset_type: server, laptop, desktop, virtual_machine, container
        - ip_address: Primary IP address
        - mac_address: Primary MAC address
        - serial_number: Hardware serial number
        - location: Physical/virtual location
        - department: Business unit/department
        - owner: Asset owner/responsible person
        - business_criticality: 1-4 (1=Critical, 4=Low)
        - patch_group: Patch deployment group
        - maintenance_window: Scheduled maintenance window
        - last_patched: Last patch date
        - tags: Comma-separated tags
        - data_quality_score: 0-100 (calculated)
        - source: Original data source
        - ingested_at: Ingestion timestamp
    """
    
    def __init__(self):
        """Initialize the normalizer."""
        self.normalized_data: Optional[pd.DataFrame] = None
        self.normalization_stats: Dict[str, Any] = {}
    
    def normalize_servicenow_export(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize a ServiceNow CMDB export to standard schema.
        
        Args:
            df: Raw ServiceNow DataFrame
            
        Returns:
            Normalized DataFrame
        """
        normalized = pd.DataFrame()
        
        # Direct mappings
        normalized['asset_id'] = df['sys_id']
        normalized['hostname'] = df['name']
        normalized['serial_number'] = df.get('serial_number', '')
        normalized['asset_type'] = df.get('model_category', 'unknown').str.lower()
        normalized['ip_address'] = df.get('ip_address', '')
        normalized['mac_address'] = df.get('mac_address', '')
        normalized['location'] = df.get('location', '')
        normalized['department'] = df.get('department', '')
        normalized['owner'] = df.get('assigned_to', '')
        normalized['patch_group'] = df.get('u_patch_group', '')
        normalized['maintenance_window'] = df.get('u_maintenance_window', '')
        
        # Normalize OS and version (ServiceNow uses 'operating_system' not 'os')
        os_field = 'operating_system' if 'operating_system' in df.columns else 'os'
        normalized['os'] = df[os_field].apply(self._normalize_os_name)
        normalized['os_version'] = df['os_version'].apply(self._normalize_os_version)
        normalized['os_build'] = df.get('os_build', df.get('os_service_pack', ''))
        
        # Normalize business criticality (ServiceNow uses 1-4, we keep the same)
        normalized['business_criticality'] = pd.to_numeric(
            df.get('business_criticality', 3), 
            errors='coerce'
        ).fillna(3).astype(int)
        
        # Parse dates
        if 'last_patched' in df.columns:
            normalized['last_patched'] = pd.to_datetime(
                df['last_patched'], 
                errors='coerce'
            )
        else:
            normalized['last_patched'] = pd.NaT
        
        # Handle tags
        normalized['tags'] = df.get('tags', '')
        
        # Add metadata
        normalized['source'] = 'servicenow'
        normalized['ingested_at'] = datetime.now()
        
        # Calculate data quality score
        normalized['data_quality_score'] = normalized.apply(
            self._calculate_data_quality, 
            axis=1
        )
        
        self.normalized_data = normalized
        self._calculate_stats(df, normalized)
        
        return normalized
    
    def normalize_generic(self, df: pd.DataFrame, field_mapping: Dict[str, str]) -> pd.DataFrame:
        """
        Normalize generic asset data with custom field mapping.
        
        Args:
            df: Raw DataFrame
            field_mapping: Dictionary mapping standard fields to source columns
                         e.g., {'hostname': 'computer_name', 'os': 'operating_system'}
        
        Returns:
            Normalized DataFrame
        """
        normalized = pd.DataFrame()
        
        # Define standard schema with defaults
        standard_fields = {
            'asset_id': '',
            'hostname': '',
            'os': 'Unknown',
            'os_version': '',
            'os_build': '',
            'asset_type': 'unknown',
            'ip_address': '',
            'mac_address': '',
            'serial_number': '',
            'location': '',
            'department': '',
            'owner': '',
            'business_criticality': 3,
            'patch_group': '',
            'maintenance_window': '',
            'last_patched': pd.NaT,
            'tags': ''
        }
        
        # Map fields from source data
        for std_field, default_value in standard_fields.items():
            if std_field in field_mapping and field_mapping[std_field] in df.columns:
                source_col = field_mapping[std_field]
                normalized[std_field] = df[source_col]
            else:
                normalized[std_field] = default_value
        
        # Apply normalization functions
        normalized['os'] = normalized['os'].apply(self._normalize_os_name)
        normalized['os_version'] = normalized['os_version'].apply(self._normalize_os_version)
        normalized['asset_type'] = normalized['asset_type'].str.lower()
        
        # Add metadata
        normalized['source'] = 'generic'
        normalized['ingested_at'] = datetime.now()
        
        # Calculate data quality score
        normalized['data_quality_score'] = normalized.apply(
            self._calculate_data_quality, 
            axis=1
        )
        
        self.normalized_data = normalized
        self._calculate_stats(df, normalized)
        
        return normalized
    
    def _normalize_os_name(self, os_name: str) -> str:
        """
        Normalize operating system names to standard format.
        
        Args:
            os_name: Raw OS name
            
        Returns:
            Normalized OS name
        """
        if pd.isna(os_name) or not os_name:
            return "Unknown"
        
        os_name = str(os_name).strip()
        os_lower = os_name.lower()
        
        # Windows variants
        if 'windows server 2022' in os_lower:
            return "Windows Server 2022"
        elif 'windows server 2019' in os_lower:
            return "Windows Server 2019"
        elif 'windows server 2016' in os_lower:
            return "Windows Server 2016"
        elif 'windows server 2012' in os_lower:
            if 'r2' in os_lower:
                return "Windows Server 2012 R2"
            return "Windows Server 2012"
        elif 'windows 11' in os_lower:
            return "Windows 11"
        elif 'windows 10' in os_lower:
            return "Windows 10"
        elif 'windows' in os_lower:
            return "Windows"
        
        # Linux variants
        elif 'ubuntu' in os_lower:
            return "Ubuntu Linux"
        elif 'red hat' in os_lower or 'rhel' in os_lower:
            return "Red Hat Enterprise Linux"
        elif 'centos' in os_lower:
            return "CentOS"
        elif 'debian' in os_lower:
            return "Debian"
        elif 'linux' in os_lower:
            return "Linux"
        
        # macOS
        elif 'macos' in os_lower or 'mac os' in os_lower:
            return "macOS"
        
        return os_name
    
    def _normalize_os_version(self, version: str) -> str:
        """
        Normalize OS version strings.
        
        Args:
            version: Raw version string
            
        Returns:
            Normalized version string
        """
        if pd.isna(version) or not version:
            return ""
        
        version = str(version).strip()
        
        # Extract version numbers (e.g., "10.0.19045" from longer strings)
        version_pattern = r'\d+\.\d+(?:\.\d+)?(?:\.\d+)?'
        match = re.search(version_pattern, version)
        
        if match:
            return match.group(0)
        
        return version
    
    def _calculate_data_quality(self, row: pd.Series) -> int:
        """
        Calculate data quality score (0-100) based on field completeness and validity.
        
        Scoring:
            - Critical fields (hostname, os, os_version): 40 points
            - Important fields (ip_address, owner, criticality): 30 points
            - Useful fields (location, department, tags): 20 points
            - Optional fields (serial, mac, patch_group): 10 points
        
        Args:
            row: Asset record as Series
            
        Returns:
            Data quality score (0-100)
        """
        score = 0
        
        # Critical fields (40 points total)
        if row['hostname'] and row['hostname'] != '':
            score += 15
        if row['os'] and row['os'] not in ['Unknown', '', 'unknown']:
            score += 15
        if row['os_version'] and row['os_version'] != '':
            score += 10
        
        # Important fields (30 points total)
        if row['ip_address'] and row['ip_address'] != '':
            score += 10
        if row['owner'] and row['owner'] != '':
            score += 10
        if row['business_criticality'] and row['business_criticality'] > 0:
            score += 10
        
        # Useful fields (20 points total)
        if row['location'] and row['location'] != '':
            score += 7
        if row['department'] and row['department'] != '':
            score += 7
        if row['tags'] and row['tags'] != '':
            score += 6
        
        # Optional fields (10 points total)
        if row['serial_number'] and row['serial_number'] != '':
            score += 4
        if row['mac_address'] and row['mac_address'] != '':
            score += 3
        if row['patch_group'] and row['patch_group'] != '':
            score += 3
        
        return min(score, 100)  # Cap at 100
    
    def _calculate_stats(self, raw_df: pd.DataFrame, normalized_df: pd.DataFrame) -> None:
        """
        Calculate normalization statistics.
        
        Args:
            raw_df: Original raw DataFrame
            normalized_df: Normalized DataFrame
        """
        self.normalization_stats = {
            'raw_records': len(raw_df),
            'normalized_records': len(normalized_df),
            'records_dropped': len(raw_df) - len(normalized_df),
            'avg_data_quality': normalized_df['data_quality_score'].mean(),
            'min_data_quality': normalized_df['data_quality_score'].min(),
            'max_data_quality': normalized_df['data_quality_score'].max(),
            'os_normalized': normalized_df['os'].value_counts().to_dict(),
            'asset_types': normalized_df['asset_type'].value_counts().to_dict(),
            'criticality_distribution': normalized_df['business_criticality'].value_counts().to_dict(),
            'fields_with_nulls': normalized_df.isnull().sum().to_dict(),
            'normalized_at': datetime.now().isoformat()
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get normalization statistics.
        
        Returns:
            Dictionary containing normalization stats
        """
        return self.normalization_stats
    
    def get_normalized_data(self) -> pd.DataFrame:
        """
        Get the normalized data.
        
        Returns:
            Normalized DataFrame
        """
        if self.normalized_data is None:
            raise ValueError("No normalized data available")
        
        return self.normalized_data
    
    def save_to_csv(self, filepath: str) -> None:
        """
        Save normalized data to CSV file.
        
        Args:
            filepath: Output file path
        """
        if self.normalized_data is None:
            raise ValueError("No normalized data to save")
        
        self.normalized_data.to_csv(filepath, index=False)
    
    def save_to_json(self, filepath: str) -> None:
        """
        Save normalized data to JSON file.
        
        Args:
            filepath: Output file path
        """
        if self.normalized_data is None:
            raise ValueError("No normalized data to save")
        
        self.normalized_data.to_json(filepath, orient='records', indent=2, date_format='iso')
