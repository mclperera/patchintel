#!/usr/bin/env python3
"""
PatchIntel Risk Engine
Entry point for risk scoring CLI.
"""

import sys
from pathlib import Path

# Add src directory to path
src_dir = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_dir))

from cli import cli

if __name__ == '__main__':
    cli()
