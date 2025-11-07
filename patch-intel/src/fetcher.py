"""
Microsoft Patch Tuesday Data Fetcher
Retrieves vulnerability data from Microsoft Security Update Guide API
"""

import requests
import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class MicrosoftPatchFetcher:
    """
    Fetches Microsoft Patch Tuesday data from the Security Update Guide API
    """
    
    # Microsoft Security Update Guide API endpoint
    BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the fetcher with optional API key
        
        Args:
            api_key: Microsoft API key (if required for enhanced access)
        """
        self.api_key = api_key
        self.session = requests.Session()
        
        # Set headers
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'PatchIntel/1.0'
        }
        
        if api_key:
            headers['api-key'] = api_key
            
        self.session.headers.update(headers)
    
    def get_updates_list(self) -> List[str]:
        """
        Get list of available security update IDs
        
        Returns:
            List of update IDs (format: YYYY-MMM)
        """
        try:
            url = f"{self.BASE_URL}/updates"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            return data.get('value', [])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching updates list: {e}")
            return []
    
    def fetch_patch_tuesday_data(self, year_month: str) -> Optional[Dict]:
        """
        Fetch Patch Tuesday data for a specific month
        
        Args:
            year_month: Format YYYY-MM (e.g., '2024-11')
            
        Returns:
            Dictionary containing vulnerability data
        """
        try:
            # Convert format from YYYY-MM to YYYY-MMM (e.g., 2024-Nov)
            date_obj = datetime.strptime(year_month, '%Y-%m')
            formatted_date = date_obj.strftime('%Y-%b')
            
            url = f"{self.BASE_URL}/cvrf/{formatted_date}"
            print(f"Fetching data from: {url}")
            
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"No data found for {year_month}")
            else:
                print(f"HTTP Error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error fetching patch data: {e}")
            return None
        except ValueError as e:
            print(f"Invalid date format. Please use YYYY-MM format: {e}")
            return None
    
    def fetch_multiple_months(self, months: List[str]) -> Dict[str, Dict]:
        """
        Fetch data for multiple months
        
        Args:
            months: List of month strings in YYYY-MM format
            
        Returns:
            Dictionary mapping month to its data
        """
        results = {}
        
        for month in months:
            print(f"\nFetching data for {month}...")
            data = self.fetch_patch_tuesday_data(month)
            if data:
                results[month] = data
                print(f"✓ Successfully fetched data for {month}")
            else:
                print(f"✗ Failed to fetch data for {month}")
        
        return results
    
    def save_to_json(self, data: Dict, output_path: str):
        """
        Save fetched data to JSON file
        
        Args:
            data: Data to save
            output_path: Path to output file
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ Data saved to {output_path}")
            
        except Exception as e:
            print(f"Error saving JSON: {e}")
    
    def save_to_csv(self, data: Dict, output_path: str):
        """
        Save parsed vulnerability data to CSV
        
        Args:
            data: Parsed vulnerability data
            output_path: Path to output CSV file
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Extract vulnerabilities from the CVRF document
            vulnerabilities = self._extract_vulnerabilities(data)
            
            if not vulnerabilities:
                print("No vulnerabilities found to save")
                return
            
            # Define CSV columns
            fieldnames = [
                'cve_id', 'title', 'severity', 'cvss_score', 'cvss_vector',
                'description', 'product', 'kb_article', 'exploit_status',
                'release_date', 'impact_type', 'affected_platforms'
            ]
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(vulnerabilities)
            
            print(f"✓ CSV data saved to {output_path}")
            print(f"  Total vulnerabilities: {len(vulnerabilities)}")
            
        except Exception as e:
            print(f"Error saving CSV: {e}")
    
    def _extract_vulnerabilities(self, data: Dict) -> List[Dict]:
        """
        Extract and flatten vulnerability information from CVRF document
        
        Args:
            data: Raw CVRF data
            
        Returns:
            List of flattened vulnerability dictionaries
        """
        vulnerabilities = []
        
        try:
            # Navigate the CVRF structure
            document = data
            
            # Get document metadata
            doc_title = document.get('DocumentTitle', {}).get('Value', '')
            doc_tracking = document.get('DocumentTracking', {})
            release_date = doc_tracking.get('CurrentReleaseDate', '')
            
            # Extract vulnerabilities
            vuln_list = document.get('Vulnerability', [])
            
            for vuln in vuln_list:
                # Extract CVE ID
                cve_id = vuln.get('CVE', '')
                
                # Extract title
                title = vuln.get('Title', {}).get('Value', '')
                
                # Extract severity and CVSS
                threat_list = vuln.get('Threats', [])
                severity = ''
                impact_type = ''
                
                for threat in threat_list:
                    if threat.get('Type') == 0:  # Severity rating
                        severity = threat.get('Description', {}).get('Value', '')
                    elif threat.get('Type') == 1:  # Impact
                        impact_type = threat.get('Description', {}).get('Value', '')
                
                # Extract CVSS
                cvss_sets = vuln.get('CVSSScoreSets', [])
                cvss_score = ''
                cvss_vector = ''
                
                if cvss_sets:
                    cvss_score = cvss_sets[0].get('BaseScore', '')
                    cvss_vector = cvss_sets[0].get('Vector', '')
                
                # Extract description/notes
                notes = vuln.get('Notes', [])
                description = ''
                for note in notes:
                    if note.get('Type') == 1:  # Description
                        description = note.get('Value', '')
                        break
                
                # Extract products
                product_statuses = vuln.get('ProductStatuses', [])
                products = []
                for status in product_statuses:
                    if status.get('Type') == 1:  # Known affected
                        products.extend(status.get('ProductID', []))
                
                # Extract KB articles
                remediations = vuln.get('Remediations', [])
                kb_articles = []
                for remediation in remediations:
                    if remediation.get('Type') == 2:  # Vendor Fix
                        kb_articles.extend(remediation.get('Supercedence', []))
                
                # Extract exploit status
                exploit_status = 'Unknown'
                for threat in threat_list:
                    if threat.get('Type') == 3:  # Exploit status
                        exploit_status = threat.get('Description', {}).get('Value', '')
                        break
                
                # Create vulnerability record
                vuln_record = {
                    'cve_id': cve_id,
                    'title': title,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'description': description[:500] if description else '',  # Truncate long descriptions
                    'product': ', '.join(products[:5]) if products else '',  # First 5 products
                    'kb_article': ', '.join(kb_articles) if kb_articles else '',
                    'exploit_status': exploit_status,
                    'release_date': release_date,
                    'impact_type': impact_type,
                    'affected_platforms': str(len(products))
                }
                
                vulnerabilities.append(vuln_record)
        
        except Exception as e:
            print(f"Error extracting vulnerabilities: {e}")
        
        return vulnerabilities
