"""
Risk Engine CLI
Command-line interface for CVE-asset matching and risk scoring.
"""

import click
import pandas as pd
from pathlib import Path
import json

from config_loader import load_config, get_default_config
from matcher import load_and_match, CVEAssetMatcher
from calculator import RiskCalculator


@click.group()
def cli():
    """PatchIntel Risk Engine - Calculate risk scores for CVE-asset pairs."""
    pass


@cli.command()
@click.option('--cve-data', required=True, help='Path to CVE data CSV (from patch-intel)')
@click.option('--asset-data', required=True, help='Path to asset data CSV (from asset-ingestion)')
@click.option('--config', default='config/risk_scoring.yaml', help='Path to risk scoring config YAML')
@click.option('--output', default='output/risk_scores.csv', help='Output path for scored risks')
@click.option('--matches-output', default='output/cve_asset_matches.csv', help='Output path for CVE-asset matches')
def calculate(cve_data, asset_data, config, output, matches_output):
    """Calculate risk scores for all CVE-asset pairs."""
    
    click.echo("🎯 PatchIntel Risk Engine - Risk Calculation")
    click.echo("=" * 60)
    
    # Load configuration
    click.echo(f"\n📋 Loading configuration from {config}...")
    try:
        risk_config = load_config(config)
        click.echo(f"   ✓ Loaded: {risk_config.name} v{risk_config.version}")
    except FileNotFoundError:
        click.echo(f"   ⚠️  Config not found, using default configuration")
        risk_config = get_default_config()
    
    # Step 1: Match CVEs to assets
    click.echo(f"\n🔗 Step 1: Matching CVEs to Assets")
    click.echo(f"   CVE Data: {cve_data}")
    click.echo(f"   Asset Data: {asset_data}")
    
    matcher = load_and_match(cve_data, asset_data)
    
    if len(matcher.matches) == 0:
        click.echo("   ❌ No matches found! Check if OS/versions align.")
        return
    
    # Export matches
    matches_path = Path(matches_output)
    matches_path.parent.mkdir(parents=True, exist_ok=True)
    matcher.export_matches(matches_output)
    
    # Show matching stats
    stats = matcher.get_stats()
    click.echo(f"\n   Match Statistics:")
    click.echo(f"   • Total Matches: {stats['total_matches']}")
    click.echo(f"   • Assets Affected: {stats['unique_assets_affected']}/{stats['total_assets']} ({stats['assets_affected_percentage']}%)")
    click.echo(f"   • CVEs Applicable: {stats['unique_cves_matched']}/{stats['total_cves']} ({stats['cves_applicable_percentage']}%)")
    click.echo(f"   • Avg CVEs per Asset: {stats['avg_cves_per_asset']}")
    
    # Step 2: Calculate risk scores
    click.echo(f"\n📊 Step 2: Calculating Risk Scores")
    click.echo(f"   Using 6 core dials:")
    click.echo(f"   1. CVSS Base Score (foundation)")
    click.echo(f"   2. Business Criticality (0.5x - 2.0x)")
    click.echo(f"   3. Exploit Status (0.5x - 3.0x)")
    click.echo(f"   4. Severity Type (0.8x - 2.0x)")
    click.echo(f"   5. Age/Freshness (1.0x - 1.5x)")
    click.echo(f"   6. Asset Type (0.9x - 1.3x)")
    
    calculator = RiskCalculator(risk_config)
    scored_risks = calculator.calculate_bulk(matcher.matches)
    
    # Export scored risks
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    calculator.export_scored_risks(scored_risks, output)
    
    # Show risk summary
    summary = calculator.get_risk_summary(scored_risks)
    
    click.echo(f"\n   Risk Score Statistics:")
    click.echo(f"   • Range: {summary['risk_score_stats']['min']} - {summary['risk_score_stats']['max']}")
    click.echo(f"   • Mean: {summary['risk_score_stats']['mean']}")
    click.echo(f"   • Median: {summary['risk_score_stats']['median']}")
    
    click.echo(f"\n   Priority Band Distribution:")
    for band, count in summary['by_priority_band'].items():
        percentage = round(100 * count / summary['total_risks'], 1)
        click.echo(f"   • {band}: {count} ({percentage}%)")
    
    click.echo(f"\n   Top 5 Highest Risk Assets:")
    for i, risk in enumerate(summary['top_10_risks'][:5], 1):
        click.echo(f"   {i}. {risk['hostname']} - {risk['cve_id']} - Score: {risk['risk_score']} ({risk['priority_band']})")
    
    click.echo(f"\n✅ Complete! Results saved to:")
    click.echo(f"   • Matches: {matches_output}")
    click.echo(f"   • Risk Scores: {output}")


@cli.command()
@click.option('--cve-data', required=True, help='Path to CVE data CSV')
@click.option('--asset-data', required=True, help='Path to asset data CSV')
@click.option('--output', default='output/cve_asset_matches.csv', help='Output path for matches')
def match(cve_data, asset_data, output):
    """Match CVEs to assets (without risk scoring)."""
    
    click.echo("🔗 CVE-Asset Matching")
    click.echo("=" * 60)
    
    matcher = load_and_match(cve_data, asset_data)
    
    if len(matcher.matches) == 0:
        click.echo("\n❌ No matches found! Check if OS/versions align.")
        return
    
    # Export matches
    matcher.export_matches(output)
    
    # Show stats
    stats = matcher.get_stats()
    
    click.echo(f"\n📊 Matching Statistics:")
    click.echo(f"   Total Matches: {stats['total_matches']}")
    click.echo(f"   Assets Affected: {stats['unique_assets_affected']}/{stats['total_assets']}")
    click.echo(f"   CVEs Applicable: {stats['unique_cves_matched']}/{stats['total_cves']}")
    
    click.echo(f"\n🏆 Top 10 Most Vulnerable Assets:")
    top_assets = matcher.get_top_vulnerable_assets(10)
    for idx, row in top_assets.iterrows():
        click.echo(f"   {row['hostname']}: {row['cve_count']} CVEs (Criticality: {row['business_criticality']}, Type: {row['asset_type']})")
    
    click.echo(f"\n🌐 Top 10 Most Widespread CVEs:")
    top_cves = matcher.get_most_widespread_cves(10)
    for idx, row in top_cves.iterrows():
        click.echo(f"   {row['cve_id']}: {row['affected_assets']} assets (Severity: {row['severity']}, CVSS: {row['cvss_score']})")
    
    click.echo(f"\n✅ Matches exported to {output}")


@cli.command()
@click.option('--scored-data', required=True, help='Path to scored risks CSV')
@click.option('--min-score', default=90.0, help='Minimum risk score for critical risks')
def critical(scored_data, min_score):
    """Show critical risks above threshold."""
    
    click.echo(f"🚨 Critical Risks (Score >= {min_score})")
    click.echo("=" * 60)
    
    scored_df = pd.read_csv(scored_data)
    critical_risks = scored_df[scored_df['risk_score'] >= min_score].copy()
    critical_risks = critical_risks.sort_values('risk_score', ascending=False)
    
    if len(critical_risks) == 0:
        click.echo(f"\n✅ No critical risks found above score {min_score}")
        return
    
    click.echo(f"\nFound {len(critical_risks)} critical risks:\n")
    
    for idx, risk in critical_risks.iterrows():
        click.echo(f"🔴 Risk Score: {risk['risk_score']} - {risk['priority_band']}")
        click.echo(f"   Asset: {risk['hostname']} ({risk['asset_id']})")
        click.echo(f"   CVE: {risk['cve_id']} - {risk.get('title', 'N/A')[:60]}")
        click.echo(f"   Severity: {risk['severity']} | CVSS: {risk['cvss_base']}")
        click.echo(f"   Multipliers: Crit={risk['criticality_mult']}x, Exploit={risk['exploit_mult']}x, Severity={risk['severity_mult']}x")
        click.echo(f"   Action: {risk.get('priority_action', 'Patch immediately')}")
        if risk.get('priority_sla_hours'):
            click.echo(f"   SLA: {risk['priority_sla_hours']} hours")
        click.echo()


@cli.command()
@click.option('--scored-data', required=True, help='Path to scored risks CSV')
@click.option('--asset-id', required=True, help='Asset ID to query')
def asset_risks(scored_data, asset_id):
    """Show all risks for a specific asset."""
    
    click.echo(f"🖥️  Risks for Asset: {asset_id}")
    click.echo("=" * 60)
    
    scored_df = pd.read_csv(scored_data)
    asset_risks = scored_df[scored_df['asset_id'] == asset_id].copy()
    asset_risks = asset_risks.sort_values('risk_score', ascending=False)
    
    if len(asset_risks) == 0:
        click.echo(f"\n❌ No risks found for asset {asset_id}")
        return
    
    # Asset summary
    first_risk = asset_risks.iloc[0]
    click.echo(f"\nAsset Information:")
    click.echo(f"   Hostname: {first_risk['hostname']}")
    click.echo(f"   OS: {first_risk['os']} {first_risk['os_version']}")
    click.echo(f"   Criticality: Level {first_risk['business_criticality']}")
    click.echo(f"   Type: {first_risk['asset_type']}")
    click.echo(f"   Total Risks: {len(asset_risks)}")
    
    # Risk distribution
    click.echo(f"\nRisk Distribution:")
    for band in ['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        count = len(asset_risks[asset_risks['priority_band'] == band])
        if count > 0:
            click.echo(f"   {band}: {count}")
    
    # Top risks
    click.echo(f"\nTop 10 Risks:")
    for idx, risk in asset_risks.head(10).iterrows():
        click.echo(f"   {risk['risk_score']:.1f} - {risk['cve_id']} - {risk['severity']} - {risk['priority_band']}")


@cli.command()
@click.option('--scored-data', required=True, help='Path to scored risks CSV')
@click.option('--cve-id', required=True, help='CVE ID to query')
def cve_impact(scored_data, cve_id):
    """Show all assets affected by a specific CVE."""
    
    click.echo(f"🔍 Impact Analysis: {cve_id}")
    click.echo("=" * 60)
    
    scored_df = pd.read_csv(scored_data)
    cve_risks = scored_df[scored_df['cve_id'] == cve_id].copy()
    cve_risks = cve_risks.sort_values('risk_score', ascending=False)
    
    if len(cve_risks) == 0:
        click.echo(f"\n❌ CVE {cve_id} does not affect any assets in inventory")
        return
    
    # CVE summary
    first_risk = cve_risks.iloc[0]
    click.echo(f"\nCVE Information:")
    click.echo(f"   Title: {first_risk.get('title', 'N/A')}")
    click.echo(f"   Severity: {first_risk['severity']}")
    click.echo(f"   CVSS: {first_risk['cvss_base']}")
    click.echo(f"   Impact Type: {first_risk.get('impact_type', 'N/A')}")
    click.echo(f"   Age: {first_risk['age_days']} days")
    click.echo(f"   Affected Assets: {len(cve_risks)}")
    
    # Risk distribution
    click.echo(f"\nRisk Distribution:")
    click.echo(f"   Highest Risk: {cve_risks['risk_score'].max():.1f}")
    click.echo(f"   Lowest Risk: {cve_risks['risk_score'].min():.1f}")
    click.echo(f"   Average Risk: {cve_risks['risk_score'].mean():.1f}")
    
    # Priority bands
    click.echo(f"\nPriority Distribution:")
    for band in ['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        count = len(cve_risks[cve_risks['priority_band'] == band])
        if count > 0:
            click.echo(f"   {band}: {count}")
    
    # Top affected assets
    click.echo(f"\nTop 10 Highest Risk Assets:")
    for idx, risk in cve_risks.head(10).iterrows():
        click.echo(f"   {risk['risk_score']:.1f} - {risk['hostname']} (Crit: {risk['business_criticality']}, Type: {risk['asset_type']})")


@cli.command()
@click.option('--scored-data', required=True, help='Path to scored risks CSV')
def summary(scored_data):
    """Show summary statistics for risk scores."""
    
    click.echo("📈 Risk Scoring Summary")
    click.echo("=" * 60)
    
    scored_df = pd.read_csv(scored_data)
    
    click.echo(f"\n📊 Overall Statistics:")
    click.echo(f"   Total Risks: {len(scored_df)}")
    click.echo(f"   Unique Assets: {scored_df['asset_id'].nunique()}")
    click.echo(f"   Unique CVEs: {scored_df['cve_id'].nunique()}")
    
    click.echo(f"\n🎯 Risk Score Distribution:")
    click.echo(f"   Min: {scored_df['risk_score'].min():.2f}")
    click.echo(f"   Max: {scored_df['risk_score'].max():.2f}")
    click.echo(f"   Mean: {scored_df['risk_score'].mean():.2f}")
    click.echo(f"   Median: {scored_df['risk_score'].median():.2f}")
    
    click.echo(f"\n🚦 Priority Band Distribution:")
    for band in ['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        count = len(scored_df[scored_df['priority_band'] == band])
        percentage = 100 * count / len(scored_df)
        if count > 0:
            click.echo(f"   {band}: {count} ({percentage:.1f}%)")
    
    click.echo(f"\n🔧 Average Multipliers:")
    click.echo(f"   Criticality: {scored_df['criticality_mult'].mean():.2f}x")
    click.echo(f"   Exploit: {scored_df['exploit_mult'].mean():.2f}x")
    click.echo(f"   Severity: {scored_df['severity_mult'].mean():.2f}x")
    click.echo(f"   Age: {scored_df['age_mult'].mean():.2f}x")
    click.echo(f"   Asset Type: {scored_df['asset_type_mult'].mean():.2f}x")


if __name__ == '__main__':
    cli()
