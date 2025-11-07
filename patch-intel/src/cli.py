"""
PatchIntel CLI - Command-line interface for Patch Tuesday data operations
"""

import click
import json
from pathlib import Path
from typing import Optional

from fetcher import MicrosoftPatchFetcher
from parser import PatchDataParser


@click.group()
@click.version_option(version="0.1.0", prog_name="PatchIntel")
def cli():
    """
    PatchIntel - Microsoft Patch Tuesday Intelligence Tool
    
    Fetch, parse, and analyze Microsoft Patch Tuesday vulnerability data.
    """
    pass


@cli.command()
@click.option(
    '--month',
    required=True,
    help='Month in YYYY-MM format (e.g., 2024-11)'
)
@click.option(
    '--api-key',
    default=None,
    envvar='MSRC_API_KEY',
    help='Microsoft API key (optional, can also use MSRC_API_KEY env var)'
)
@click.option(
    '--output-dir',
    default='./samples',
    type=click.Path(),
    help='Output directory for data'
)
@click.option(
    '--format',
    type=click.Choice(['json', 'csv', 'both'], case_sensitive=False),
    default='both',
    help='Output format'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose output'
)
def fetch(month: str, api_key: Optional[str], output_dir: str, format: str, verbose: bool):
    """
    Fetch Microsoft Patch Tuesday data from Security Update Guide API.
    
    Examples:
    
        \b
        # Fetch November 2024 Patch Tuesday
        patchintel fetch --month 2024-11
        
        \b
        # Fetch with API key and custom output
        patchintel fetch --month 2024-10 --api-key YOUR_KEY --output-dir /data
        
        \b
        # Fetch JSON only
        patchintel fetch --month 2024-09 --format json
    """
    click.echo("=" * 60)
    click.echo("PatchIntel - Microsoft Patch Tuesday Fetcher")
    click.echo("=" * 60)
    
    if verbose:
        click.echo(f"Month: {month}")
        click.echo(f"Output directory: {output_dir}")
        click.echo(f"Format: {format}")
    
    # Initialize fetcher
    fetcher = MicrosoftPatchFetcher(api_key=api_key)
    
    # Fetch data
    with click.progressbar(length=1, label='Fetching data') as bar:
        data = fetcher.fetch_patch_tuesday_data(month)
        bar.update(1)
    
    if not data:
        click.echo("\n❌ Failed to fetch data. Please check:", err=True)
        click.echo("  - Month format is correct (YYYY-MM)", err=True)
        click.echo("  - Data exists for the specified month", err=True)
        click.echo("  - Your internet connection", err=True)
        raise click.Abort()
    
    # Prepare output paths
    month_safe = month.replace('-', '_')
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    json_path = output_dir_path / f"patch_tuesday_{month_safe}.json"
    csv_path = output_dir_path / f"patch_tuesday_{month_safe}.csv"
    
    # Save data
    if format in ['json', 'both']:
        fetcher.save_to_json(data, str(json_path))
    
    if format in ['csv', 'both']:
        fetcher.save_to_csv(data, str(csv_path))
    
    click.echo(f"\n✅ Successfully retrieved Patch Tuesday data for {month}!")


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option(
    '--output-dir',
    type=click.Path(),
    help='Output directory for normalized data (optional)'
)
@click.option(
    '--format',
    type=click.Choice(['json', 'csv', 'both'], case_sensitive=False),
    default='both',
    help='Output format for normalized data'
)
@click.option(
    '--stats-only',
    is_flag=True,
    help='Only display statistics, do not save normalized data'
)
def parse(input_file: str, output_dir: Optional[str], format: str, stats_only: bool):
    """
    Parse and normalize raw Patch Tuesday data.
    
    INPUT_FILE: Path to raw JSON file from fetch command
    
    Examples:
    
        \b
        # Parse and show statistics
        patchintel parse samples/patch_tuesday_2024_11.json
        
        \b
        # Parse and save normalized output
        patchintel parse samples/patch_tuesday_2024_11.json --output-dir normalized/
        
        \b
        # Parse and save JSON only
        patchintel parse samples/patch_tuesday_2024_11.json --output-dir normalized/ --format json
    """
    try:
        # Load raw data
        click.echo(f"Loading data from {input_file}...")
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
        
        # Parse data
        click.echo("Parsing and normalizing data...")
        parser = PatchDataParser(raw_data)
        
        with click.progressbar(length=1, label='Processing') as bar:
            parser.parse()
            bar.update(1)
        
        # Display summary
        parser.print_summary()
        
        # Save normalized data if output directory specified and not stats-only
        if output_dir and not stats_only:
            input_path = Path(input_file)
            base_name = input_path.stem.replace('patch_tuesday_', 'normalized_')
            
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            json_output = output_path / f"{base_name}.json"
            csv_output = output_path / f"{base_name}.csv"
            
            if format in ['json', 'both']:
                parser.save_normalized_json(str(json_output))
            
            if format in ['csv', 'both']:
                parser.save_normalized_csv(str(csv_output))
            
            click.echo(f"\n✅ Normalized data saved to {output_dir}")
        elif stats_only:
            click.echo("\nℹ️  Statistics only mode - no files saved")
        
    except FileNotFoundError:
        click.echo(f"❌ Error: File not found: {input_file}", err=True)
        raise click.Abort()
    except json.JSONDecodeError:
        click.echo(f"❌ Error: Invalid JSON in file: {input_file}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Error parsing file: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.option(
    '--month',
    required=True,
    help='Month in YYYY-MM format (e.g., 2024-11)'
)
@click.option(
    '--api-key',
    default=None,
    envvar='MSRC_API_KEY',
    help='Microsoft API key (optional)'
)
@click.option(
    '--output-dir',
    default='./samples',
    type=click.Path(),
    help='Output directory'
)
def process(month: str, api_key: Optional[str], output_dir: str):
    """
    Fetch and parse Patch Tuesday data in one command.
    
    This is a convenience command that combines fetch and parse operations.
    
    Example:
    
        \b
        # Fetch and parse in one step
        patchintel process --month 2024-11
    """
    click.echo("=" * 60)
    click.echo("PatchIntel - Fetch & Parse Pipeline")
    click.echo("=" * 60)
    
    # Step 1: Fetch
    click.echo("\n[1/2] Fetching data...")
    fetcher = MicrosoftPatchFetcher(api_key=api_key)
    data = fetcher.fetch_patch_tuesday_data(month)
    
    if not data:
        click.echo("\n❌ Failed to fetch data", err=True)
        raise click.Abort()
    
    # Save raw data
    month_safe = month.replace('-', '_')
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    json_path = output_dir_path / f"patch_tuesday_{month_safe}.json"
    fetcher.save_to_json(data, str(json_path))
    
    # Step 2: Parse
    click.echo("\n[2/2] Parsing and normalizing...")
    parser = PatchDataParser(data)
    parser.parse()
    parser.print_summary()
    
    # Save normalized data
    normalized_dir = output_dir_path / "normalized"
    normalized_dir.mkdir(exist_ok=True)
    
    norm_json = normalized_dir / f"normalized_{month_safe}.json"
    norm_csv = normalized_dir / f"normalized_{month_safe}.csv"
    
    parser.save_normalized_json(str(norm_json))
    parser.save_normalized_csv(str(norm_csv))
    
    click.echo(f"\n✅ Complete! Data saved to {output_dir}")


@cli.command()
def info():
    """
    Display information about the PatchIntel module.
    """
    click.echo("=" * 60)
    click.echo("PatchIntel - Patch Tuesday Intelligence Module")
    click.echo("=" * 60)
    click.echo("\nVersion: 0.1.0")
    click.echo("Module: patch-intel (Phase 1)")
    click.echo("\nCapabilities:")
    click.echo("  ✓ Fetch Microsoft Patch Tuesday data")
    click.echo("  ✓ Parse CVRF vulnerability documents")
    click.echo("  ✓ Normalize CVE information")
    click.echo("  ✓ Generate vulnerability statistics")
    click.echo("  ✓ Export to JSON and CSV formats")
    click.echo("\nData Sources:")
    click.echo("  • Microsoft Security Update Guide API")
    click.echo("  • https://api.msrc.microsoft.com/cvrf/v2.0")
    click.echo("\nFor detailed documentation:")
    click.echo("  See: patch-intel/README.md")
    click.echo("=" * 60)


if __name__ == '__main__':
    cli()
