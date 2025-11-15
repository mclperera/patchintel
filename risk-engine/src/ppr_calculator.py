"""
PPR Calculator
Calculates Patch Priority Rating (PPR) scores using additive scoring framework.
"""

import pandas as pd
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

from ppr_config_loader import PPRConfig


class PPRCalculator:
    """
    Calculates PPR scores for CVE-asset pairs using additive scoring.
    
    Formula:
    PPR = Exploitation + CVSS + AttackVector + Privilege + Impact + Exposure
    
    Maximum Score: 175 points (50+25+20+20+30+30)
    """
    
    def __init__(self, config: PPRConfig):
        """
        Initialize calculator with PPR configuration.
        
        Args:
            config: PPR scoring configuration
        """
        self.config = config
        self.current_date = datetime.now()
    
    def calculate_single_ppr(self,
                            cvss_score: Optional[float],
                            impact_type_field: str,
                            attack_vector: str,
                            privileges_required: str,
                            severity: str,
                            asset_exposure: str) -> Dict[str, any]:
        """
        Calculate PPR score for a single CVE-asset pair.
        
        Args:
            cvss_score: CVSS base score (0-10), None if missing
            impact_type_field: Raw impact_type field (contains exploitation status)
            attack_vector: Attack vector from CVSS (N/A/L/P or full name)
            privileges_required: Privileges required from CVSS (N/L/H or full name)
            severity: CVE severity/impact type (Remote Code Execution, etc.)
            asset_exposure: Asset exposure category (internet_facing, etc.)
            
        Returns:
            Dictionary with:
                - ppr_score: Final PPR score (0-175)
                - exploitation_points: Points from exploitation status
                - cvss_points: Points from CVSS score
                - attack_vector_points: Points from attack vector
                - privilege_points: Points from privileges required
                - impact_type_points: Points from impact/severity type
                - exposure_points: Points from asset exposure
                - exploitation_status: Parsed exploitation status
                - priority_band: Priority band information
        """
        # Component 1: Exploitation Status (0-50 points)
        exploitation_status = self.config.parse_exploitation_status(impact_type_field)
        exploitation_points = self.config.get_exploitation_points(exploitation_status)
        
        # Component 2: CVSS Score (0-25 points)
        cvss_points = self.config.get_cvss_points(cvss_score)
        
        # Component 3: Attack Vector (0-20 points)
        attack_vector_points = self.config.get_attack_vector_points(attack_vector)
        
        # Component 4: Privileges Required (0-20 points)
        privilege_points = self.config.get_privilege_points(privileges_required)
        
        # Component 5: Impact Type (0-30 points)
        impact_type_points = self.config.get_impact_type_points(severity)
        
        # Component 6: Asset Exposure (0-30 points)
        exposure_points = self.config.get_exposure_points(asset_exposure)
        
        # Calculate total PPR score
        ppr_score = (
            exploitation_points +
            cvss_points +
            attack_vector_points +
            privilege_points +
            impact_type_points +
            exposure_points
        )
        
        # Get priority band
        priority_band = self.config.get_priority_band(ppr_score)
        
        return {
            'ppr_score': ppr_score,
            'exploitation_points': exploitation_points,
            'cvss_points': cvss_points,
            'attack_vector_points': attack_vector_points,
            'privilege_points': privilege_points,
            'impact_type_points': impact_type_points,
            'exposure_points': exposure_points,
            'exploitation_status': exploitation_status,
            'priority_band': priority_band['label'],
            'priority_action': priority_band['action'],
            'priority_color': priority_band['color']
        }
    
    def calculate_bulk_ppr(self, matches_df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate PPR scores for bulk CVE-asset matches.
        
        Args:
            matches_df: DataFrame with CVE-asset matches
                Required columns:
                    - cvss_score (or cvss_base_score)
                    - impact_type
                    - attack_vector
                    - privileges_required
                    - severity
                    - asset_exposure
        
        Returns:
            DataFrame with original data plus PPR scoring columns
        """
        print(f"Calculating PPR scores for {len(matches_df)} matches...")
        
        # Create copy to avoid modifying original
        results = matches_df.copy()
        
        # Normalize column names if needed
        if 'cvss_base_score' in results.columns and 'cvss_score' not in results.columns:
            results['cvss_score'] = results['cvss_base_score']
        
        # Calculate PPR for each row
        ppr_calculations = []
        
        for idx, row in results.iterrows():
            calc = self.calculate_single_ppr(
                cvss_score=row.get('cvss_score'),
                impact_type_field=row.get('impact_type', ''),
                attack_vector=row.get('attack_vector', ''),
                privileges_required=row.get('privileges_required', ''),
                severity=row.get('severity', ''),
                asset_exposure=row.get('asset_exposure', 'unknown')
            )
            ppr_calculations.append(calc)
        
        # Add calculated columns
        ppr_df = pd.DataFrame(ppr_calculations)
        
        for col in ppr_df.columns:
            results[col] = ppr_df[col]
        
        # Sort by PPR score descending
        results = results.sort_values('ppr_score', ascending=False)
        
        print(f"PPR scores calculated. Range: {results['ppr_score'].min():.0f} - {results['ppr_score'].max():.0f}")
        print(f"Median: {results['ppr_score'].median():.0f}")
        
        return results
    
    def get_ppr_summary(self, scored_df: pd.DataFrame) -> Dict[str, any]:
        """
        Get summary statistics for PPR scores.
        
        Args:
            scored_df: DataFrame with PPR scores
            
        Returns:
            Dictionary with statistics
        """
        summary = {
            'total_risks': len(scored_df),
            'ppr_score_stats': {
                'min': int(scored_df['ppr_score'].min()),
                'max': int(scored_df['ppr_score'].max()),
                'mean': round(scored_df['ppr_score'].mean(), 1),
                'median': int(scored_df['ppr_score'].median()),
                'std': round(scored_df['ppr_score'].std(), 1)
            },
            'by_priority_band': scored_df['priority_band'].value_counts().to_dict(),
            'by_exploitation_status': scored_df['exploitation_status'].value_counts().to_dict() if 'exploitation_status' in scored_df else {},
            'by_asset_exposure': scored_df['asset_exposure'].value_counts().to_dict() if 'asset_exposure' in scored_df else {},
            'by_severity': scored_df['severity'].value_counts().to_dict() if 'severity' in scored_df else {},
            'component_averages': {
                'exploitation': round(scored_df['exploitation_points'].mean(), 1),
                'cvss': round(scored_df['cvss_points'].mean(), 1),
                'attack_vector': round(scored_df['attack_vector_points'].mean(), 1),
                'privilege': round(scored_df['privilege_points'].mean(), 1),
                'impact_type': round(scored_df['impact_type_points'].mean(), 1),
                'exposure': round(scored_df['exposure_points'].mean(), 1)
            },
            'top_10_risks': scored_df.head(10)[['asset_id', 'hostname', 'cve_id', 'ppr_score', 'priority_band']].to_dict('records') if 'asset_id' in scored_df else []
        }
        
        return summary
    
    def export_scored_risks(self, scored_df: pd.DataFrame, output_path: str):
        """
        Export scored risks to CSV file.
        
        Args:
            scored_df: DataFrame with PPR scores
            output_path: Path to output CSV file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        scored_df.to_csv(output_path, index=False)
        print(f"Exported {len(scored_df)} PPR-scored risks to {output_path}")
    
    def get_critical_risks(self, scored_df: pd.DataFrame, min_score: float = 120.0) -> pd.DataFrame:
        """
        Get critical risks above threshold (default: EMERGENCY PATCH band).
        
        Args:
            scored_df: DataFrame with PPR scores
            min_score: Minimum PPR score threshold
            
        Returns:
            DataFrame with critical risks
        """
        critical = scored_df[scored_df['ppr_score'] >= min_score].copy()
        critical = critical.sort_values('ppr_score', ascending=False)
        
        return critical
    
    def get_risks_by_asset(self, scored_df: pd.DataFrame, asset_id: str) -> pd.DataFrame:
        """
        Get all risks for a specific asset.
        
        Args:
            scored_df: DataFrame with PPR scores
            asset_id: Asset ID to filter
            
        Returns:
            DataFrame with risks for that asset
        """
        asset_risks = scored_df[scored_df['asset_id'] == asset_id].copy()
        asset_risks = asset_risks.sort_values('ppr_score', ascending=False)
        
        return asset_risks
    
    def get_risks_by_cve(self, scored_df: pd.DataFrame, cve_id: str) -> pd.DataFrame:
        """
        Get all affected assets for a specific CVE.
        
        Args:
            scored_df: DataFrame with PPR scores
            cve_id: CVE ID to filter
            
        Returns:
            DataFrame with affected assets for that CVE
        """
        cve_risks = scored_df[scored_df['cve_id'] == cve_id].copy()
        cve_risks = cve_risks.sort_values('ppr_score', ascending=False)
        
        return cve_risks
    
    def get_risks_by_priority(self, scored_df: pd.DataFrame, priority_band: str) -> pd.DataFrame:
        """
        Get all risks in a specific priority band.
        
        Args:
            scored_df: DataFrame with PPR scores
            priority_band: Priority band label (e.g., "🔴 EMERGENCY PATCH")
            
        Returns:
            DataFrame with risks in that priority band
        """
        priority_risks = scored_df[scored_df['priority_band'] == priority_band].copy()
        priority_risks = priority_risks.sort_values('ppr_score', ascending=False)
        
        return priority_risks
    
    def print_ppr_summary(self, scored_df: pd.DataFrame):
        """
        Print a formatted summary of PPR scores.
        
        Args:
            scored_df: DataFrame with PPR scores
        """
        summary = self.get_ppr_summary(scored_df)
        
        print("\n" + "=" * 80)
        print("PPR SCORING SUMMARY")
        print("=" * 80)
        
        print(f"\nTotal CVE-Asset Pairs: {summary['total_risks']}")
        
        stats = summary['ppr_score_stats']
        print(f"\nPPR Score Statistics:")
        print(f"  Range: {stats['min']} - {stats['max']}")
        print(f"  Mean: {stats['mean']}")
        print(f"  Median: {stats['median']}")
        print(f"  Std Dev: {stats['std']}")
        
        print(f"\n🚦 Priority Band Distribution:")
        total = summary['total_risks']
        for band, count in sorted(summary['by_priority_band'].items()):
            pct = (count / total * 100) if total > 0 else 0
            print(f"  {band:30s}: {count:4d} ({pct:5.1f}%)")
        
        print(f"\n⚠️  Exploitation Status Distribution:")
        for status, count in sorted(summary['by_exploitation_status'].items()):
            print(f"  {status:30s}: {count:4d}")
        
        print(f"\n📊 Average Component Scores:")
        comp = summary['component_averages']
        print(f"  Exploitation Status : {comp['exploitation']:5.1f} / 50")
        print(f"  CVSS Score         : {comp['cvss']:5.1f} / 25")
        print(f"  Attack Vector      : {comp['attack_vector']:5.1f} / 20")
        print(f"  Privileges Required: {comp['privilege']:5.1f} / 20")
        print(f"  Impact Type        : {comp['impact_type']:5.1f} / 30")
        print(f"  Asset Exposure     : {comp['exposure']:5.1f} / 30")
        
        if summary['top_10_risks']:
            print(f"\n🔥 Top 10 Highest Priority Risks:")
            for i, risk in enumerate(summary['top_10_risks'], 1):
                print(f"  {i:2d}. {risk.get('hostname', 'N/A'):20s} | {risk.get('cve_id', 'N/A'):20s} | PPR: {risk.get('ppr_score', 0):3.0f} | {risk.get('priority_band', 'N/A')}")
        
        print("=" * 80 + "\n")


def load_ppr_calculator(config_path: str) -> PPRCalculator:
    """
    Load PPR calculator with configuration.
    
    Args:
        config_path: Path to PPR YAML configuration
        
    Returns:
        PPRCalculator instance
    """
    from ppr_config_loader import load_ppr_config
    config = load_ppr_config(config_path)
    return PPRCalculator(config)

