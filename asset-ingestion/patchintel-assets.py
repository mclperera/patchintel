#!/usr/bin/env python3
"""
PatchIntel Assets - Main Entry Point
Asset ingestion and normalization for PatchIntel
"""

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from cli import cli

if __name__ == "__main__":
    cli()
