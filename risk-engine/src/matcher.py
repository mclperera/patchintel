"""
CVE-to-Asset Matcher
Correlates CVE data with asset inventory based on operating system and version.
"""

import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re


class CVEAssetMatcher:
    """
    Matches CVEs to assets based on affected products and asset OS/version.
    """
    
    def __init__(self, cve_data: pd.DataFrame, asset_data: pd.DataFrame):
        """
        Initialize matcher with CVE and asset data.
        
        Args:
            cve_data: DataFrame with CVE information (from patch-intel)
            asset_data: DataFrame with normalized asset information (from asset-ingestion)
        """
        self.cve_data = cve_data.copy()
        self.asset_data = asset_data.copy()
        self.matches = None
        
        # Clean and prepare data
        self._prepare_data()
    
    def _prepare_data(self):
        """Prepare CVE and asset data for matching."""
        # Ensure required columns exist
        required_cve_cols = ['cve_id', 'title']
        required_asset_cols = ['asset_id', 'hostname', 'os', 'os_version']
        
        for col in required_cve_cols:
            if col not in self.cve_data.columns:
                raise ValueError(f"CVE data missing required column: {col}")
        
        for col in required_asset_cols:
            if col not in self.asset_data.columns:
                raise ValueError(f"Asset data missing required column: {col}")
        
        # Normalize OS strings for easier matching
        self.asset_data['os_normalized'] = self.asset_data['os'].apply(self._normalize_os_string)
        self.asset_data['os_version_normalized'] = self.asset_data['os_version'].apply(self._normalize_version_string)
    
    def _normalize_os_string(self, os_string: str) -> str:
        """
        Normalize OS string for matching.
        
        Args:
            os_string: Operating system string
            
        Returns:
            Normalized OS string
        """
        if pd.isna(os_string):
            return ""
        
        os_lower = str(os_string).lower().strip()
        
        # Normalize Windows versions
        if 'windows' in os_lower:
            # Extract version numbers
            if 'server 2022' in os_lower or '2022' in os_lower:
                return 'windows_server_2022'
            elif 'server 2019' in os_lower or '2019' in os_lower:
                return 'windows_server_2019'
            elif 'server 2016' in os_lower or '2016' in os_lower:
                return 'windows_server_2016'
            elif 'windows 11' in os_lower or 'win11' in os_lower:
                return 'windows_11'
            elif 'windows 10' in os_lower or 'win10' in os_lower:
                return 'windows_10'
            else:
                return 'windows_unknown'
        
        return os_lower
    
    def _normalize_version_string(self, version_string: str) -> str:
        """
        Normalize version string for matching.
        
        Args:
            version_string: OS version string
            
        Returns:
            Normalized version string
        """
        if pd.isna(version_string):
            return ""
        
        version_lower = str(version_string).lower().strip()
        
        # Extract major version numbers
        # Example: "21H2", "22H2", "10.0.19045"
        return version_lower
    
    def _check_product_match(self, title: str, asset_os: str, asset_version: str) -> bool:
        """
        Check if an asset's OS/version matches the CVE's title (which contains product info).
        
        Args:
            title: CVE title containing product information
            asset_os: Normalized asset OS string
            asset_version: Normalized asset version string
            
        Returns:
            True if asset is affected by CVE
        """
        if pd.isna(title):
            return False
        
        title_lower = str(title).lower()
        
        # Windows Server 2022
        if asset_os == 'windows_server_2022':
            if 'windows server 2022' in title_lower:
                return True
        
        # Windows Server 2019
        if asset_os == 'windows_server_2019':
            if 'windows server 2019' in title_lower:
                return True
        
        # Windows Server 2016
        if asset_os == 'windows_server_2016':
            if 'windows server 2016' in title_lower:
                return True
        
        # Windows 11
        if asset_os == 'windows_11':
            if 'windows 11' in title_lower:
                # Check version if specified
                if asset_version:
                    if '22h2' in asset_version and '22h2' in title_lower:
                        return True
                    elif '21h2' in asset_version and '21h2' in title_lower:
                        return True
                    elif 'version' not in title_lower:
                        # CVE affects all Windows 11 versions
                        return True
                else:
                    return True
        
        # Windows 10
        if asset_os == 'windows_10':
            if 'windows 10' in title_lower:
                # Check version if specified
                if asset_version:
                    if '22h2' in asset_version and '22h2' in title_lower:
                        return True
                    elif '21h2' in asset_version and '21h2' in title_lower:
                        return True
                    elif '20h2' in asset_version and '20h2' in title_lower:
                        return True
                    elif 'version' not in title_lower:
                        # CVE affects all Windows 10 versions
                        return True
                else:
                    return True
        
        # Generic Windows match (if CVE just says "Windows" without specific version)
        if asset_os.startswith('windows_') and 'windows' in title_lower:
            # Avoid false positives - only match if it's truly generic
            if not any(specific in title_lower for specific in 
                      ['server 2022', 'server 2019', 'server 2016', 'windows 11', 'windows 10']):
                return True
        
        return False
    
    def match(self) -> pd.DataFrame:
        """
        Match CVEs to assets.
        
        Returns:
            DataFrame with columns:
                - asset_id
                - hostname
                - os
                - os_version
                - business_criticality
                - asset_type
                - cve_id
                - title
                - severity
                - cvss_score
                - impact_type
                - affected_products
                - release_date
        """
        matches = []
        
        print(f"Matching {len(self.cve_data)} CVEs to {len(self.asset_data)} assets...")
        
        # Iterate through each asset
        for _, asset in self.asset_data.iterrows():
            asset_os = asset['os_normalized']
            asset_version = asset['os_version_normalized']
            
            # Check each CVE
            for _, cve in self.cve_data.iterrows():
                if self._check_product_match(cve['title'], asset_os, asset_version):
                    # Create match record
                    match = {
                        # Asset information
                        'asset_id': asset['asset_id'],
                        'hostname': asset['hostname'],
                        'os': asset['os'],
                        'os_version': asset['os_version'],
                        'business_criticality': asset.get('business_criticality', 3),
                        'asset_type': asset.get('asset_type', 'unknown'),
                        'location': asset.get('location', 'unknown'),
                        'department': asset.get('department', 'unknown'),
                        'patch_group': asset.get('patch_group', 'unknown'),
                        
                        # CVE information
                        'cve_id': cve['cve_id'],
                        'title': cve.get('title', ''),
                        'severity': cve.get('severity', ''),
                        'cvss_score': cve.get('cvss_score', None),
                        'impact_type': cve.get('impact_type', ''),
                        'product': cve.get('product', ''),
                        'affected_platforms': cve.get('affected_platforms', ''),
                        'release_date': cve.get('release_date', ''),
                        'kb_article': cve.get('kb_article', ''),
                        'exploit_status': cve.get('exploit_status', '')
                    }
                    
                    matches.append(match)
        
        self.matches = pd.DataFrame(matches)
        
        print(f"Found {len(self.matches)} CVE-asset matches")
        
        return self.matches
    
    def get_stats(self) -> Dict[str, any]:
        """
        Get matching statistics.
        
        Returns:
            Dictionary with statistics
        """
        if self.matches is None:
            return {"error": "No matching performed yet. Call match() first."}
        
        stats = {
            'total_matches': len(self.matches),
            'unique_assets_affected': self.matches['asset_id'].nunique(),
            'unique_cves_matched': self.matches['cve_id'].nunique(),
            'total_assets': len(self.asset_data),
            'total_cves': len(self.cve_data),
            'assets_affected_percentage': round(100 * self.matches['asset_id'].nunique() / len(self.asset_data), 2),
            'cves_applicable_percentage': round(100 * self.matches['cve_id'].nunique() / len(self.cve_data), 2),
            'avg_cves_per_asset': round(len(self.matches) / self.matches['asset_id'].nunique(), 2) if self.matches['asset_id'].nunique() > 0 else 0,
            'avg_assets_per_cve': round(len(self.matches) / self.matches['cve_id'].nunique(), 2) if self.matches['cve_id'].nunique() > 0 else 0,
        }
        
        # Breakdown by severity
        if 'severity' in self.matches.columns:
            stats['by_severity'] = self.matches['severity'].value_counts().to_dict()
        
        # Breakdown by asset type
        if 'asset_type' in self.matches.columns:
            stats['by_asset_type'] = self.matches['asset_type'].value_counts().to_dict()
        
        # Breakdown by criticality
        if 'business_criticality' in self.matches.columns:
            stats['by_criticality'] = self.matches['business_criticality'].value_counts().to_dict()
        
        return stats
    
    def get_top_vulnerable_assets(self, top_n: int = 10) -> pd.DataFrame:
        """
        Get assets with the most CVE matches.
        
        Args:
            top_n: Number of top assets to return
            
        Returns:
            DataFrame with asset vulnerability counts
        """
        if self.matches is None:
            raise ValueError("No matching performed yet. Call match() first.")
        
        vulnerable_assets = self.matches.groupby(['asset_id', 'hostname', 'os', 'business_criticality', 'asset_type']).agg({
            'cve_id': 'count'
        }).reset_index()
        
        vulnerable_assets.columns = ['asset_id', 'hostname', 'os', 'business_criticality', 'asset_type', 'cve_count']
        vulnerable_assets = vulnerable_assets.sort_values('cve_count', ascending=False).head(top_n)
        
        return vulnerable_assets
    
    def get_most_widespread_cves(self, top_n: int = 10) -> pd.DataFrame:
        """
        Get CVEs that affect the most assets.
        
        Args:
            top_n: Number of top CVEs to return
            
        Returns:
            DataFrame with CVE impact counts
        """
        if self.matches is None:
            raise ValueError("No matching performed yet. Call match() first.")
        
        widespread_cves = self.matches.groupby(['cve_id', 'title', 'severity', 'cvss_score']).agg({
            'asset_id': 'count'
        }).reset_index()
        
        widespread_cves.columns = ['cve_id', 'title', 'severity', 'cvss_score', 'affected_assets']
        widespread_cves = widespread_cves.sort_values('affected_assets', ascending=False).head(top_n)
        
        return widespread_cves
    
    def export_matches(self, output_path: str):
        """
        Export matches to CSV file.
        
        Args:
            output_path: Path to output CSV file
        """
        if self.matches is None:
            raise ValueError("No matching performed yet. Call match() first.")
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.matches.to_csv(output_path, index=False)
        print(f"Exported {len(self.matches)} matches to {output_path}")


def load_and_match(cve_path: str, asset_path: str) -> CVEAssetMatcher:
    """
    Load CVE and asset data, then perform matching.
    
    Args:
        cve_path: Path to CVE data CSV
        asset_path: Path to asset data CSV
        
    Returns:
        CVEAssetMatcher with matches computed
    """
    print(f"Loading CVE data from {cve_path}")
    cve_data = pd.read_csv(cve_path)
    
    print(f"Loading asset data from {asset_path}")
    asset_data = pd.read_csv(asset_path)
    
    matcher = CVEAssetMatcher(cve_data, asset_data)
    matcher.match()
    
    return matcher
