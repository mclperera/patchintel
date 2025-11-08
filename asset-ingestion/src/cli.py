"""
CLI for Asset Ingestion Module
Provides command-line interface for loading, normalizing, and validating asset data.
"""

import click
import json
from pathlib import Path
from ingestion import AssetIngestor
from normalizer import AssetNormalizer


@click.group()
def cli():
    """PatchIntel Asset Ingestion - Load and normalize asset data from various sources."""
    pass


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--source-type', '-s', 
              type=click.Choice(['servicenow', 'csv', 'json'], case_sensitive=False),
              default='servicenow',
              help='Type of input source')
@click.option('--preview', '-p', is_flag=True, help='Show data preview')
def ingest(input_file, source_type, preview):
    """
    Ingest asset data from a file.
    
    Example:
        patchintel-assets ingest samples/servicenow_cmdb_export.csv -s servicenow --preview
    """
    click.echo(f"📥 Loading asset data from {input_file}...")
    
    ingestor = AssetIngestor()
    
    try:
        # Load based on source type
        if source_type == 'servicenow':
            df = ingestor.load_servicenow_export(input_file)
        elif source_type == 'csv':
            df = ingestor.load_csv(input_file)
        elif source_type == 'json':
            df = ingestor.load_json(input_file)
        
        click.echo(f"✅ Successfully loaded {len(df)} assets")
        
        # Show summary
        summary = ingestor.get_summary()
        click.echo(f"\n📊 Summary:")
        click.echo(f"   Total Assets: {summary['total_assets']}")
        click.echo(f"   Columns: {len(summary['columns'])}")
        click.echo(f"   Memory Usage: {summary['memory_usage_mb']:.2f} MB")
        
        # OS breakdown
        if 'os_breakdown' in summary:
            click.echo(f"\n💻 OS Breakdown:")
            for os, count in summary['os_breakdown'].items():
                click.echo(f"   {os}: {count}")
        
        # Asset type breakdown
        if 'asset_type_breakdown' in summary:
            click.echo(f"\n🖥️  Asset Type Breakdown:")
            for asset_type, count in summary['asset_type_breakdown'].items():
                click.echo(f"   {asset_type}: {count}")
        
        # Criticality breakdown
        if 'criticality_breakdown' in summary:
            click.echo(f"\n⚠️  Business Criticality:")
            crit_labels = {1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low'}
            for level, count in sorted(summary['criticality_breakdown'].items()):
                label = crit_labels.get(level, f'Level {level}')
                click.echo(f"   {label}: {count}")
        
        # Preview data
        if preview:
            click.echo(f"\n👀 Data Preview:")
            preview_df = ingestor.preview_data(3)
            click.echo(preview_df.to_string())
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--source-type', '-s',
              type=click.Choice(['servicenow', 'generic'], case_sensitive=False),
              default='servicenow',
              help='Type of input source')
@click.option('--format', '-f',
              type=click.Choice(['csv', 'json'], case_sensitive=False),
              default='csv',
              help='Output format')
@click.option('--stats', is_flag=True, help='Show normalization statistics')
def normalize(input_file, output_file, source_type, format, stats):
    """
    Normalize asset data to standard schema.
    
    Example:
        patchintel-assets normalize samples/servicenow_cmdb_export.csv output/normalized.csv
    """
    click.echo(f"🔄 Normalizing asset data from {input_file}...")
    
    # Step 1: Ingest
    ingestor = AssetIngestor()
    
    try:
        if source_type == 'servicenow':
            df = ingestor.load_servicenow_export(input_file)
        else:
            df = ingestor.load_csv(input_file)
        
        click.echo(f"✅ Loaded {len(df)} assets")
        
        # Step 2: Normalize
        normalizer = AssetNormalizer()
        
        if source_type == 'servicenow':
            normalized_df = normalizer.normalize_servicenow_export(df)
        else:
            # For generic, use default mapping
            field_mapping = {
                'hostname': 'name',
                'os': 'os',
                'os_version': 'os_version'
            }
            normalized_df = normalizer.normalize_generic(df, field_mapping)
        
        click.echo(f"✅ Normalized {len(normalized_df)} assets")
        
        # Step 3: Save
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'csv':
            normalizer.save_to_csv(output_file)
        else:
            normalizer.save_to_json(output_file)
        
        click.echo(f"💾 Saved to {output_file}")
        
        # Show statistics
        if stats:
            click.echo(f"\n📊 Normalization Statistics:")
            norm_stats = normalizer.get_statistics()
            
            click.echo(f"   Raw Records: {norm_stats['raw_records']}")
            click.echo(f"   Normalized Records: {norm_stats['normalized_records']}")
            click.echo(f"   Records Dropped: {norm_stats['records_dropped']}")
            click.echo(f"   Avg Data Quality: {norm_stats['avg_data_quality']:.1f}/100")
            click.echo(f"   Min Data Quality: {norm_stats['min_data_quality']}/100")
            click.echo(f"   Max Data Quality: {norm_stats['max_data_quality']}/100")
            
            click.echo(f"\n💻 Normalized OS Distribution:")
            for os, count in norm_stats['os_normalized'].items():
                click.echo(f"   {os}: {count}")
            
            click.echo(f"\n📈 Data Quality by Asset:")
            quality_summary = normalized_df.groupby('data_quality_score').size().sort_index(ascending=False)
            for score, count in quality_summary.head(5).items():
                click.echo(f"   Score {score}: {count} assets")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--min-quality', '-q', default=50, help='Minimum data quality score (0-100)')
def validate(input_file, min_quality):
    """
    Validate asset data quality.
    
    Example:
        patchintel-assets validate samples/servicenow_cmdb_export.csv --min-quality 70
    """
    click.echo(f"🔍 Validating asset data from {input_file}...")
    
    try:
        # Load and normalize
        ingestor = AssetIngestor()
        df = ingestor.load_servicenow_export(input_file)
        
        normalizer = AssetNormalizer()
        normalized_df = normalizer.normalize_servicenow_export(df)
        
        # Analyze quality
        total_assets = len(normalized_df)
        high_quality = len(normalized_df[normalized_df['data_quality_score'] >= min_quality])
        low_quality = total_assets - high_quality
        
        avg_quality = normalized_df['data_quality_score'].mean()
        
        click.echo(f"\n📊 Data Quality Report:")
        click.echo(f"   Total Assets: {total_assets}")
        click.echo(f"   Average Quality Score: {avg_quality:.1f}/100")
        click.echo(f"   High Quality (≥{min_quality}): {high_quality} ({high_quality/total_assets*100:.1f}%)")
        click.echo(f"   Low Quality (<{min_quality}): {low_quality} ({low_quality/total_assets*100:.1f}%)")
        
        # Show assets with low quality
        if low_quality > 0:
            click.echo(f"\n⚠️  Assets Below Quality Threshold:")
            low_qual_assets = normalized_df[normalized_df['data_quality_score'] < min_quality]
            for _, asset in low_qual_assets.iterrows():
                missing_fields = []
                if not asset['hostname']:
                    missing_fields.append('hostname')
                if asset['os'] == 'Unknown':
                    missing_fields.append('os')
                if not asset['os_version']:
                    missing_fields.append('os_version')
                if not asset['ip_address']:
                    missing_fields.append('ip_address')
                if not asset['owner']:
                    missing_fields.append('owner')
                
                click.echo(f"   {asset['hostname'] or 'N/A'} (Score: {asset['data_quality_score']})")
                click.echo(f"      Missing: {', '.join(missing_fields)}")
        else:
            click.echo(f"\n✅ All assets meet quality threshold!")
        
        # Field completeness
        click.echo(f"\n📋 Field Completeness:")
        important_fields = ['hostname', 'os', 'os_version', 'ip_address', 'owner', 
                          'business_criticality', 'patch_group']
        for field in important_fields:
            non_null = normalized_df[field].notna().sum()
            completeness = non_null / total_assets * 100
            status = "✅" if completeness >= 80 else "⚠️" if completeness >= 50 else "❌"
            click.echo(f"   {status} {field}: {completeness:.1f}%")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
def stats(input_file):
    """
    Show detailed statistics about asset data.
    
    Example:
        patchintel-assets stats samples/servicenow_cmdb_export.csv
    """
    click.echo(f"📊 Analyzing asset data from {input_file}...")
    
    try:
        # Load and normalize
        ingestor = AssetIngestor()
        df = ingestor.load_servicenow_export(input_file)
        
        normalizer = AssetNormalizer()
        normalized_df = normalizer.normalize_servicenow_export(df)
        
        norm_stats = normalizer.get_statistics()
        
        # General stats
        click.echo(f"\n📈 General Statistics:")
        click.echo(f"   Total Assets: {norm_stats['normalized_records']}")
        click.echo(f"   Average Data Quality: {norm_stats['avg_data_quality']:.1f}/100")
        
        # OS distribution
        click.echo(f"\n💻 Operating Systems:")
        for os, count in sorted(norm_stats['os_normalized'].items(), key=lambda x: x[1], reverse=True):
            pct = count / norm_stats['normalized_records'] * 100
            click.echo(f"   {os}: {count} ({pct:.1f}%)")
        
        # Asset types
        click.echo(f"\n🖥️  Asset Types:")
        for asset_type, count in sorted(norm_stats['asset_types'].items(), key=lambda x: x[1], reverse=True):
            pct = count / norm_stats['normalized_records'] * 100
            click.echo(f"   {asset_type}: {count} ({pct:.1f}%)")
        
        # Criticality distribution
        click.echo(f"\n⚠️  Business Criticality:")
        crit_labels = {1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low'}
        for level, count in sorted(norm_stats['criticality_distribution'].items()):
            label = crit_labels.get(level, f'Level {level}')
            pct = count / norm_stats['normalized_records'] * 100
            click.echo(f"   {label}: {count} ({pct:.1f}%)")
        
        # Patch groups
        if 'patch_group' in normalized_df.columns:
            patch_groups = normalized_df['patch_group'].value_counts()
            if len(patch_groups) > 0:
                click.echo(f"\n🔄 Patch Groups:")
                for group, count in patch_groups.items():
                    if group and group != '':
                        pct = count / norm_stats['normalized_records'] * 100
                        click.echo(f"   Group {group}: {count} ({pct:.1f}%)")
        
        # Data quality distribution
        click.echo(f"\n✨ Data Quality Distribution:")
        quality_ranges = [
            (90, 100, "Excellent"),
            (75, 89, "Good"),
            (50, 74, "Fair"),
            (0, 49, "Poor")
        ]
        for min_q, max_q, label in quality_ranges:
            count = len(normalized_df[
                (normalized_df['data_quality_score'] >= min_q) & 
                (normalized_df['data_quality_score'] <= max_q)
            ])
            pct = count / norm_stats['normalized_records'] * 100
            click.echo(f"   {label} ({min_q}-{max_q}): {count} ({pct:.1f}%)")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise click.Abort()


if __name__ == '__main__':
    cli()
