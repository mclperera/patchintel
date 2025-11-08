"""
Asset Ingestion Module
Handles loading asset data from various sources (ServiceNow, CSV, API, etc.)
"""

import pandas as pd
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class AssetIngestor:
    """
    Handles ingestion of asset data from multiple sources.
    Supports ServiceNow exports, CSV files, and JSON formats.
    """
    
    def __init__(self):
        """Initialize the asset ingestor."""
        self.raw_data: Optional[pd.DataFrame] = None
        self.source_type: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
    
    def load_servicenow_export(self, filepath: str) -> pd.DataFrame:
        """
        Load a ServiceNow CMDB export CSV file.
        
        Args:
            filepath: Path to the ServiceNow CSV export
            
        Returns:
            DataFrame containing the raw asset data
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file format is invalid
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Asset file not found: {filepath}")
        
        # Read CSV with error handling
        try:
            df = pd.read_csv(filepath)
        except Exception as e:
            raise ValueError(f"Failed to read CSV file: {e}")
        
        # Validate required ServiceNow columns
        # ServiceNow typically uses 'operating_system' not 'os'
        required_columns = ['sys_id', 'name']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")
        
        # Check for OS field (can be 'os' or 'operating_system')
        if 'os' not in df.columns and 'operating_system' not in df.columns:
            raise ValueError("Missing OS field: need either 'os' or 'operating_system' column")
        
        # Store metadata
        self.metadata = {
            'source': str(filepath),
            'source_type': 'servicenow_csv',
            'loaded_at': datetime.now().isoformat(),
            'total_records': len(df),
            'columns': list(df.columns)
        }
        
        self.raw_data = df
        self.source_type = 'servicenow_csv'
        
        return df
    
    def load_csv(self, filepath: str, column_mapping: Optional[Dict[str, str]] = None) -> pd.DataFrame:
        """
        Load a generic CSV file with optional column mapping.
        
        Args:
            filepath: Path to the CSV file
            column_mapping: Dictionary mapping source columns to standard names
                          e.g., {'hostname': 'name', 'operating_system': 'os'}
        
        Returns:
            DataFrame containing the raw asset data
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Asset file not found: {filepath}")
        
        try:
            df = pd.read_csv(filepath)
        except Exception as e:
            raise ValueError(f"Failed to read CSV file: {e}")
        
        # Apply column mapping if provided
        if column_mapping:
            df = df.rename(columns=column_mapping)
        
        # Store metadata
        self.metadata = {
            'source': str(filepath),
            'source_type': 'generic_csv',
            'loaded_at': datetime.now().isoformat(),
            'total_records': len(df),
            'columns': list(df.columns),
            'column_mapping': column_mapping
        }
        
        self.raw_data = df
        self.source_type = 'generic_csv'
        
        return df
    
    def load_json(self, filepath: str) -> pd.DataFrame:
        """
        Load asset data from a JSON file.
        Supports both array of objects and nested structures.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            DataFrame containing the raw asset data
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Asset file not found: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                # If the data is a dict with an 'assets' or 'records' key
                if 'assets' in data:
                    df = pd.DataFrame(data['assets'])
                elif 'records' in data:
                    df = pd.DataFrame(data['records'])
                else:
                    # Try to convert the dict directly
                    df = pd.DataFrame([data])
            else:
                raise ValueError("Unsupported JSON structure")
                
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON file: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load JSON file: {e}")
        
        # Store metadata
        self.metadata = {
            'source': str(filepath),
            'source_type': 'json',
            'loaded_at': datetime.now().isoformat(),
            'total_records': len(df),
            'columns': list(df.columns)
        }
        
        self.raw_data = df
        self.source_type = 'json'
        
        return df
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the loaded asset data.
        
        Returns:
            Dictionary containing summary statistics
        """
        if self.raw_data is None:
            return {'error': 'No data loaded'}
        
        df = self.raw_data
        
        summary = {
            'metadata': self.metadata,
            'total_assets': len(df),
            'columns': list(df.columns),
            'memory_usage_mb': df.memory_usage(deep=True).sum() / 1024 / 1024,
            'null_counts': df.isnull().sum().to_dict(),
            'dtypes': df.dtypes.astype(str).to_dict()
        }
        
        # Add OS breakdown if available
        if 'os' in df.columns:
            summary['os_breakdown'] = df['os'].value_counts().to_dict()
        
        # Add asset type breakdown if available
        if 'asset_type' in df.columns:
            summary['asset_type_breakdown'] = df['asset_type'].value_counts().to_dict()
        
        # Add criticality breakdown if available
        if 'business_criticality' in df.columns:
            summary['criticality_breakdown'] = df['business_criticality'].value_counts().to_dict()
        
        return summary
    
    def preview_data(self, n: int = 5) -> pd.DataFrame:
        """
        Get a preview of the loaded data.
        
        Args:
            n: Number of rows to preview
            
        Returns:
            DataFrame with first n rows
        """
        if self.raw_data is None:
            raise ValueError("No data loaded")
        
        return self.raw_data.head(n)
    
    def get_data(self) -> pd.DataFrame:
        """
        Get the raw loaded data.
        
        Returns:
            DataFrame containing the raw asset data
        """
        if self.raw_data is None:
            raise ValueError("No data loaded")
        
        return self.raw_data
