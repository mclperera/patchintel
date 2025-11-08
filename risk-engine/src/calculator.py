"""
Risk Score Calculator
Calculates risk scores using 6 core dials and configurable multipliers.
"""

import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Optional
from pathlib import Path

from config_loader import RiskScoringConfig


class RiskCalculator:
    """
    Calculates risk scores for CVE-asset pairs using 6 core dials.
    
    Formula:
    Risk Score = (CVSS × Criticality × Exploit × Severity × Age × AssetType) × 10
    Capped at 100, floored at 0
    """
    
    def __init__(self, config: RiskScoringConfig):
        """
        Initialize calculator with configuration.
        
        Args:
            config: Risk scoring configuration
        """
        self.config = config
        self.current_date = datetime.now()
    
    def calculate_age_days(self, release_date: str) -> int:
        """
        Calculate age in days from release date.
        
        Args:
            release_date: Release date string (YYYY-MM-DD format)
            
        Returns:
            Age in days
        """
        if pd.isna(release_date) or not release_date:
            return 90  # Default to 90+ days if unknown
        
        try:
            # Parse date string
            if isinstance(release_date, str):
                date_obj = datetime.strptime(release_date.split('T')[0], '%Y-%m-%d')
            else:
                date_obj = pd.to_datetime(release_date)
            
            age_days = (self.current_date - date_obj).days
            return max(0, age_days)  # Don't allow negative ages
        
        except Exception:
            return 90  # Default on error
    
    def calculate_single_risk(self, 
                             cvss_score: Optional[float],
                             business_criticality: int,
                             impact_type: str,
                             severity: str,
                             release_date: str,
                             asset_type: str) -> Dict[str, any]:
        """
        Calculate risk score for a single CVE-asset pair.
        
        Args:
            cvss_score: CVSS base score (0-10), None if missing
            business_criticality: Asset criticality level (1-4)
            impact_type: CVE impact type (contains exploit status)
            severity: CVE severity type (RCE, EoP, etc.)
            release_date: CVE release date
            asset_type: Asset type (server, laptop, desktop)
            
        Returns:
            Dictionary with:
                - risk_score: Final risk score (0-100)
                - cvss_base: CVSS score used (with default if missing)
                - criticality_mult: Business criticality multiplier
                - exploit_mult: Exploit status multiplier
                - severity_mult: Severity type multiplier
                - age_mult: Age/freshness multiplier
                - asset_type_mult: Asset type multiplier
                - age_days: Age in days
                - priority_band: Priority band information
        """
        # Dial 1: CVSS Base Score
        if pd.isna(cvss_score) or cvss_score is None:
            cvss_base = self.config.missing_cvss_default
        else:
            cvss_base = float(cvss_score)
        
        # Dial 2: Business Criticality
        criticality_mult = self.config.get_criticality_multiplier(business_criticality)
        
        # Dial 3: Exploit Status
        exploit_mult = self.config.get_exploit_multiplier(impact_type)
        
        # Dial 4: Severity Type
        severity_mult = self.config.get_severity_multiplier(severity)
        
        # Dial 5: Age/Freshness
        age_days = self.calculate_age_days(release_date)
        age_mult = self.config.get_age_multiplier(age_days)
        
        # Dial 6: Asset Type
        asset_type_mult = self.config.get_asset_type_multiplier(asset_type)
        
        # Calculate risk score
        raw_score = cvss_base * criticality_mult * exploit_mult * severity_mult * age_mult * asset_type_mult
        risk_score = raw_score * self.config.scale_factor
        
        # Apply cap and floor
        risk_score = max(self.config.floor_minimum, min(self.config.cap_maximum, risk_score))
        
        # Get priority band
        priority_band = self.config.get_priority_band(risk_score)
        
        return {
            'risk_score': round(risk_score, 2),
            'cvss_base': cvss_base,
            'criticality_mult': criticality_mult,
            'exploit_mult': exploit_mult,
            'severity_mult': severity_mult,
            'age_mult': age_mult,
            'asset_type_mult': asset_type_mult,
            'age_days': age_days,
            'priority_band': priority_band['label'],
            'priority_action': priority_band['action'],
            'priority_sla_hours': priority_band.get('sla_hours'),
            'priority_color': priority_band.get('color')
        }
    
    def calculate_bulk(self, matches_df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate risk scores for bulk CVE-asset matches.
        
        Args:
            matches_df: DataFrame with CVE-asset matches (from matcher.py)
                Must contain: cvss_score, business_criticality, impact_type,
                             severity, release_date, asset_type
        
        Returns:
            DataFrame with original data plus risk scoring columns
        """
        print(f"Calculating risk scores for {len(matches_df)} matches...")
        
        # Create copy to avoid modifying original
        results = matches_df.copy()
        
        # Calculate risk for each row
        risk_calculations = []
        
        for idx, row in results.iterrows():
            calc = self.calculate_single_risk(
                cvss_score=row.get('cvss_score'),
                business_criticality=row.get('business_criticality', 3),
                impact_type=row.get('impact_type', ''),
                severity=row.get('severity', ''),
                release_date=row.get('release_date', ''),
                asset_type=row.get('asset_type', 'unknown')
            )
            risk_calculations.append(calc)
        
        # Add calculated columns
        risk_df = pd.DataFrame(risk_calculations)
        
        for col in risk_df.columns:
            results[col] = risk_df[col]
        
        # Sort by risk score descending
        results = results.sort_values('risk_score', ascending=False)
        
        print(f"Risk scores calculated. Range: {results['risk_score'].min():.2f} - {results['risk_score'].max():.2f}")
        
        return results
    
    def get_risk_summary(self, scored_df: pd.DataFrame) -> Dict[str, any]:
        """
        Get summary statistics for risk scores.
        
        Args:
            scored_df: DataFrame with risk scores
            
        Returns:
            Dictionary with statistics
        """
        summary = {
            'total_risks': len(scored_df),
            'risk_score_stats': {
                'min': round(scored_df['risk_score'].min(), 2),
                'max': round(scored_df['risk_score'].max(), 2),
                'mean': round(scored_df['risk_score'].mean(), 2),
                'median': round(scored_df['risk_score'].median(), 2),
                'std': round(scored_df['risk_score'].std(), 2)
            },
            'by_priority_band': scored_df['priority_band'].value_counts().to_dict(),
            'by_severity': scored_df['severity'].value_counts().to_dict() if 'severity' in scored_df else {},
            'by_asset_type': scored_df['asset_type'].value_counts().to_dict() if 'asset_type' in scored_df else {},
            'by_criticality': scored_df['business_criticality'].value_counts().to_dict() if 'business_criticality' in scored_df else {},
            'multiplier_averages': {
                'criticality': round(scored_df['criticality_mult'].mean(), 2),
                'exploit': round(scored_df['exploit_mult'].mean(), 2),
                'severity': round(scored_df['severity_mult'].mean(), 2),
                'age': round(scored_df['age_mult'].mean(), 2),
                'asset_type': round(scored_df['asset_type_mult'].mean(), 2)
            },
            'top_10_risks': scored_df.head(10)[['asset_id', 'hostname', 'cve_id', 'risk_score', 'priority_band']].to_dict('records')
        }
        
        return summary
    
    def export_scored_risks(self, scored_df: pd.DataFrame, output_path: str):
        """
        Export scored risks to CSV file.
        
        Args:
            scored_df: DataFrame with risk scores
            output_path: Path to output CSV file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        scored_df.to_csv(output_path, index=False)
        print(f"Exported {len(scored_df)} scored risks to {output_path}")
    
    def get_critical_risks(self, scored_df: pd.DataFrame, min_score: float = 90.0) -> pd.DataFrame:
        """
        Get critical risks above threshold.
        
        Args:
            scored_df: DataFrame with risk scores
            min_score: Minimum risk score threshold
            
        Returns:
            DataFrame with critical risks
        """
        critical = scored_df[scored_df['risk_score'] >= min_score].copy()
        critical = critical.sort_values('risk_score', ascending=False)
        
        return critical
    
    def get_risks_by_asset(self, scored_df: pd.DataFrame, asset_id: str) -> pd.DataFrame:
        """
        Get all risks for a specific asset.
        
        Args:
            scored_df: DataFrame with risk scores
            asset_id: Asset ID to filter
            
        Returns:
            DataFrame with risks for that asset
        """
        asset_risks = scored_df[scored_df['asset_id'] == asset_id].copy()
        asset_risks = asset_risks.sort_values('risk_score', ascending=False)
        
        return asset_risks
    
    def get_risks_by_cve(self, scored_df: pd.DataFrame, cve_id: str) -> pd.DataFrame:
        """
        Get all affected assets for a specific CVE.
        
        Args:
            scored_df: DataFrame with risk scores
            cve_id: CVE ID to filter
            
        Returns:
            DataFrame with affected assets for that CVE
        """
        cve_risks = scored_df[scored_df['cve_id'] == cve_id].copy()
        cve_risks = cve_risks.sort_values('risk_score', ascending=False)
        
        return cve_risks
    
    def simulate_config_change(self, 
                               scored_df: pd.DataFrame,
                               dial_name: str,
                               new_value: float) -> pd.DataFrame:
        """
        Simulate what risk scores would be with a different multiplier.
        
        Args:
            scored_df: DataFrame with current risk scores
            dial_name: Name of dial to change (criticality_mult, exploit_mult, etc.)
            new_value: New multiplier value
            
        Returns:
            DataFrame with recalculated scores
        """
        if dial_name not in ['criticality_mult', 'exploit_mult', 'severity_mult', 'age_mult', 'asset_type_mult']:
            raise ValueError(f"Invalid dial name: {dial_name}")
        
        # Create copy
        simulated = scored_df.copy()
        
        # Recalculate risk scores with new multiplier
        # Formula: risk_score = (cvss_base × all_multipliers) × 10
        # We need to reverse-calculate, change one multiplier, then recalculate
        
        for idx, row in simulated.iterrows():
            # Get current multipliers
            mult_product = (row['criticality_mult'] * row['exploit_mult'] * 
                          row['severity_mult'] * row['age_mult'] * row['asset_type_mult'])
            
            # Replace old multiplier with new
            old_value = row[dial_name]
            new_mult_product = mult_product / old_value * new_value
            
            # Recalculate risk
            new_risk = row['cvss_base'] * new_mult_product * self.config.scale_factor
            new_risk = max(self.config.floor_minimum, min(self.config.cap_maximum, new_risk))
            
            simulated.at[idx, dial_name] = new_value
            simulated.at[idx, 'risk_score'] = round(new_risk, 2)
            
            # Update priority band
            new_band = self.config.get_priority_band(new_risk)
            simulated.at[idx, 'priority_band'] = new_band['label']
        
        return simulated.sort_values('risk_score', ascending=False)
