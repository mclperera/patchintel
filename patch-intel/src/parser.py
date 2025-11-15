"""
Microsoft Patch Tuesday Data Parser
Normalizes and structures vulnerability data from Microsoft Security Update Guide
"""

import json
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path


class PatchDataParser:
    """
    Parses and normalizes Microsoft Patch Tuesday CVRF data
    """
    
    # Severity mapping
    SEVERITY_LEVELS = {
        'Critical': 4,
        'Important': 3,
        'Moderate': 2,
        'Low': 1,
        'Unspecified': 0
    }
    
    # Exploit status mapping
    EXPLOIT_STATUS = {
        'Exploitation Detected': 'ACTIVE',
        'Exploitation More Likely': 'HIGH_RISK',
        'Exploitation Less Likely': 'LOW_RISK',
        'Exploitation Unlikely': 'UNLIKELY',
        'Unknown': 'UNKNOWN'
    }
    
    def __init__(self, raw_data: Dict):
        """
        Initialize parser with raw CVRF data
        
        Args:
            raw_data: Raw CVRF JSON data from Microsoft API
        """
        self.raw_data = raw_data
        self.normalized_data = []
    
    def parse(self) -> List[Dict]:
        """
        Parse and normalize the CVRF data
        
        Returns:
            List of normalized vulnerability dictionaries
        """
        try:
            # Get document metadata
            doc_title = self.raw_data.get('DocumentTitle', {}).get('Value', '')
            doc_tracking = self.raw_data.get('DocumentTracking', {})
            release_date = doc_tracking.get('CurrentReleaseDate', '')
            revision = doc_tracking.get('Revision', {}).get('Number', '1.0')
            
            # Get product tree for mapping product IDs to names
            product_tree = self._build_product_tree()
            
            # Extract vulnerabilities
            vulnerabilities = self.raw_data.get('Vulnerability', [])
            
            for vuln in vulnerabilities:
                normalized = self._normalize_vulnerability(
                    vuln, 
                    product_tree, 
                    release_date,
                    doc_title
                )
                self.normalized_data.append(normalized)
            
            return self.normalized_data
            
        except Exception as e:
            print(f"Error parsing data: {e}")
            return []
    
    def _build_product_tree(self) -> Dict[str, str]:
        """
        Build a mapping of Product IDs to Product Names
        
        Returns:
            Dictionary mapping product ID to product name
        """
        product_map = {}
        
        try:
            product_tree = self.raw_data.get('ProductTree', {})
            branches = product_tree.get('Branch', [])
            
            def traverse_branch(branch):
                """Recursively traverse product tree branches"""
                if 'ProductID' in branch:
                    product_id = branch.get('ProductID')
                    product_name = branch.get('Name', 'Unknown Product')
                    product_map[product_id] = product_name
                
                # Traverse child branches
                if 'Branch' in branch:
                    for child in branch.get('Branch', []):
                        traverse_branch(child)
            
            # Process all top-level branches
            for branch in branches:
                traverse_branch(branch)
            
            # Also check FullProductName entries
            full_products = product_tree.get('FullProductName', [])
            for product in full_products:
                product_id = product.get('ProductID')
                product_name = product.get('Value', 'Unknown Product')
                product_map[product_id] = product_name
                
        except Exception as e:
            print(f"Error building product tree: {e}")
        
        return product_map
    
    def _normalize_vulnerability(
        self, 
        vuln: Dict, 
        product_tree: Dict,
        release_date: str,
        doc_title: str
    ) -> Dict:
        """
        Normalize a single vulnerability entry
        
        Args:
            vuln: Raw vulnerability data
            product_tree: Product ID to name mapping
            release_date: Release date of the patch
            doc_title: Document title
            
        Returns:
            Normalized vulnerability dictionary
        """
        # Extract CVE ID
        cve_id = vuln.get('CVE', 'N/A')
        
        # Extract title
        title = vuln.get('Title', {}).get('Value', '')
        
        # Extract description
        notes = vuln.get('Notes', [])
        description = ''
        faq = ''
        
        for note in notes:
            note_type = note.get('Type')
            note_value = note.get('Value', '')
            
            if note_type == 1:  # Description
                description = note_value
            elif note_type == 4:  # FAQ
                faq = note_value
        
        # Extract threats (severity, exploit status, impact)
        threats = vuln.get('Threats', [])
        severity = 'Unknown'
        severity_value = 0
        exploit_status = 'UNKNOWN'
        exploit_status_raw = 'Unknown'
        impact_type = ''
        
        for threat in threats:
            threat_type = threat.get('Type')
            threat_desc = threat.get('Description', {}).get('Value', '')
            
            if threat_type == 0:  # Severity
                severity = threat_desc
                severity_value = self.SEVERITY_LEVELS.get(severity, 0)
            elif threat_type == 1:  # Impact
                impact_type = threat_desc
            elif threat_type == 3:  # Exploit Status
                exploit_status_raw = threat_desc
                exploit_status = self.EXPLOIT_STATUS.get(threat_desc, 'UNKNOWN')
        
        # Extract CVSS scores
        cvss_sets = vuln.get('CVSSScoreSets', [])
        cvss_base_score = 0.0
        cvss_temporal_score = 0.0
        cvss_vector = ''
        
        if cvss_sets:
            first_set = cvss_sets[0]
            cvss_base_score = float(first_set.get('BaseScore', 0))
            cvss_temporal_score = float(first_set.get('TemporalScore', 0))
            cvss_vector = first_set.get('Vector', '')
        
        # Extract affected products
        product_statuses = vuln.get('ProductStatuses', [])
        affected_products = []
        affected_product_ids = []
        
        for status in product_statuses:
            if status.get('Type') == 1:  # Known Affected
                product_ids = status.get('ProductID', [])
                affected_product_ids.extend(product_ids)
                
                # Map IDs to names
                for pid in product_ids:
                    product_name = product_tree.get(pid, f'Unknown ({pid})')
                    affected_products.append(product_name)
        
        # Extract remediation details (KB articles, supercedence)
        remediations = vuln.get('Remediations', [])
        kb_articles = []
        superceded_by = []
        restart_required = 'Unknown'
        
        for remediation in remediations:
            rem_type = remediation.get('Type')
            
            if rem_type == 2:  # Vendor Fix
                # Extract KB articles
                description_rem = remediation.get('Description', {}).get('Value', '')
                if description_rem:
                    kb_articles.append(description_rem)
                
                # Extract supercedence info
                supercedence = remediation.get('Supercedence', '')
                if supercedence:
                    superceded_by.append(supercedence)
                
                # Extract restart requirement
                restart = remediation.get('RestartRequired', {}).get('Value', 'Unknown')
                restart_required = restart
        
        # Extract acknowledgments (if any)
        acknowledgments = vuln.get('Acknowledgments', [])
        acknowledged_researchers = []
        
        for ack in acknowledgments:
            names = ack.get('Name', [])
            acknowledged_researchers.extend(names)
        
        # Build normalized structure
        normalized = {
            # Core identifiers
            'cve_id': cve_id,
            'title': title,
            'description': description,
            'faq': faq,
            
            # Severity and scoring
            'severity': severity,
            'severity_value': severity_value,
            'cvss_base_score': cvss_base_score,
            'cvss_temporal_score': cvss_temporal_score,
            'cvss_vector': cvss_vector,
            
            # Exploit information
            'exploit_status': exploit_status,
            'exploit_status_raw': exploit_status_raw,
            
            # Impact
            'impact_type': impact_type,
            
            # Affected systems
            'affected_products': affected_products,
            'affected_product_ids': affected_product_ids,
            'affected_product_count': len(affected_products),
            
            # Remediation
            'kb_articles': kb_articles,
            'superceded_by': superceded_by,
            'restart_required': restart_required,
            
            # Credits
            'acknowledged_researchers': acknowledged_researchers,
            
            # Metadata
            'release_date': release_date,
            'patch_tuesday_title': doc_title,
            'parsed_timestamp': datetime.now().isoformat()
        }
        
        return normalized
    
    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert normalized data to pandas DataFrame
        
        Returns:
            DataFrame with normalized vulnerability data
        """
        if not self.normalized_data:
            self.parse()
        
        # Flatten list fields for DataFrame
        df_data = []
        for vuln in self.normalized_data:
            flattened = vuln.copy()
            
            # Convert lists to comma-separated strings
            flattened['affected_products'] = '; '.join(vuln['affected_products'][:5])  # First 5 products
            flattened['affected_product_ids'] = '; '.join(vuln['affected_product_ids'][:5])
            flattened['kb_articles'] = '; '.join(vuln['kb_articles'])
            flattened['superceded_by'] = '; '.join(vuln['superceded_by'])
            flattened['acknowledged_researchers'] = '; '.join(vuln['acknowledged_researchers'])
            
            df_data.append(flattened)
        
        return pd.DataFrame(df_data)
    
    def save_normalized_json(self, output_path: str):
        """
        Save normalized data to JSON file
        
        Args:
            output_path: Path to output file
        """
        if not self.normalized_data:
            self.parse()
        
        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.normalized_data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ Normalized data saved to {output_path}")
            
        except Exception as e:
            print(f"Error saving normalized JSON: {e}")
    
    def save_normalized_csv(self, output_path: str):
        """
        Save normalized data to CSV file
        
        Args:
            output_path: Path to output file
        """
        try:
            df = self.to_dataframe()
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            df.to_csv(output_path, index=False, encoding='utf-8')
            
            print(f"✓ Normalized CSV saved to {output_path}")
            print(f"  Total vulnerabilities: {len(df)}")
            
        except Exception as e:
            print(f"Error saving normalized CSV: {e}")
    
    def get_statistics(self) -> Dict:
        """
        Generate statistics about the parsed data
        
        Returns:
            Dictionary with various statistics
        """
        if not self.normalized_data:
            self.parse()
        
        stats = {
            'total_vulnerabilities': len(self.normalized_data),
            'by_severity': {},
            'by_exploit_status': {},
            'with_active_exploits': 0,
            'critical_count': 0,
            'avg_cvss_score': 0.0,
            'max_cvss_score': 0.0,
            'total_affected_products': 0
        }
        
        cvss_scores = []
        
        for vuln in self.normalized_data:
            # Count by severity
            severity = vuln['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count by exploit status
            exploit_status = vuln['exploit_status']
            stats['by_exploit_status'][exploit_status] = stats['by_exploit_status'].get(exploit_status, 0) + 1
            
            # Active exploits
            if exploit_status == 'ACTIVE':
                stats['with_active_exploits'] += 1
            
            # Critical vulns
            if severity == 'Critical':
                stats['critical_count'] += 1
            
            # CVSS stats
            cvss = vuln['cvss_base_score']
            if cvss > 0:
                cvss_scores.append(cvss)
            
            # Product count
            stats['total_affected_products'] += vuln['affected_product_count']
        
        if cvss_scores:
            stats['avg_cvss_score'] = round(sum(cvss_scores) / len(cvss_scores), 2)
            stats['max_cvss_score'] = max(cvss_scores)
        
        return stats
    
    def print_summary(self):
        """
        Print a summary of the parsed data
        """
        stats = self.get_statistics()
        
        print("\n" + "=" * 60)
        print("PATCH TUESDAY DATA SUMMARY")
        print("=" * 60)
        print(f"\nTotal Vulnerabilities: {stats['total_vulnerabilities']}")
        
        print("\nBy Severity:")
        for severity, count in sorted(stats['by_severity'].items(), 
                                      key=lambda x: self.SEVERITY_LEVELS.get(x[0], 0),
                                      reverse=True):
            print(f"  {severity:15s}: {count:3d}")
        
        print("\nBy Exploit Status:")
        for status, count in sorted(stats['by_exploit_status'].items()):
            print(f"  {status:15s}: {count:3d}")
        
        print(f"\n⚠️  Vulnerabilities with Active Exploits: {stats['with_active_exploits']}")
        print(f"🔴 Critical Vulnerabilities: {stats['critical_count']}")
        print(f"\n📊 Average CVSS Score: {stats['avg_cvss_score']}")
        print(f"📊 Maximum CVSS Score: {stats['max_cvss_score']}")
        print(f"\n🖥️  Total Affected Products: {stats['total_affected_products']}")
        print("=" * 60 + "\n")
