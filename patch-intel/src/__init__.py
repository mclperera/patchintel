"""
PatchIntel - Microsoft Patch Tuesday Data Ingestion Module

This module provides tools to fetch, parse, and normalize Microsoft Patch Tuesday
vulnerability data from the Security Update Guide API.
"""

__version__ = "0.1.0"
__author__ = "PatchIntel Project"

from fetcher import MicrosoftPatchFetcher
from parser import PatchDataParser

__all__ = [
    "MicrosoftPatchFetcher",
    "PatchDataParser",
]
