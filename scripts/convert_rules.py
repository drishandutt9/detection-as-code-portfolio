#!/usr/bin/env python3
"""
Detection-as-Code: Sigma to KQL Converter
Converts Sigma rules to Kusto Query Language (KQL) for Azure Sentinel/Microsoft Defender
"""

import os
import sys
import yaml
import argparse
from pathlib import Path
from datetime import datetime


class SigmaToKQLConverter:
    """Convert Sigma detection rules to KQL queries"""
    
    def __init__(self, rules_dir, output_dir):
        self.rules_dir = Path(rules_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.conversion_stats = {
            'total': 0,
            'success': 0,
            'failed': 0
        }
    
    def load_sigma_rule(self, rule_path):
        """Load and parse Sigma rule YAML file"""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {rule_path}: {e}")
            return None
    
    def convert_to_kql(self, sigma_rule, rule_name):
        """Convert Sigma rule to KQL query"""
        
        # Extract rule metadata
        title = sigma_rule.get('title', 'Unknown')
        description = sigma_rule.get('description', '')
        level = sigma_rule.get('level', 'medium')
        
        # Determine the data source table
        logsource = sigma_rule.get('logsource', {})
        table = self.map_logsource_to_table(logsource)
        
        # Build KQL query
        kql_query = f"""// {title}
// Severity: {level.upper()}
// Description: {description}
// Rule ID: {sigma_rule.get('id', 'N/A')}
// Author: {sigma_rule.get('author', 'Unknown')}
// Date: {sigma_rule.get('date', 'N/A')}

{table}
| where TimeGenerated >= ago(24h)
{self.build_detection_logic(sigma_rule, logsource)}
| project TimeGenerated, Computer, AccountName, ProcessName, CommandLine, 
          ParentProcessName, EventID, Details = pack_all()
| extend Severity = "{level}"
| extend RuleName = "{title}"
"""
        return kql_query
    
    def map_logsource_to_table(self, logsource):
        """Map Sigma logsource to KQL table names"""
        category = logsource.get('category', '').lower()
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        
        # Mapping logic
        if category == 'process_creation':
            return 'SecurityEvent | where EventID == 4688'
        elif category == 'process_access':
            return 'SecurityEvent | where EventID == 4656'
        elif service == 'security':
            return 'SecurityEvent'
        elif 'azure' in product:
            return 'SigninLogs'
        elif 'office' in product or 'o365' in product:
            return 'OfficeActivity'
        else:
            return 'SecurityEvent'
    
    def build_detection_logic(self, sigma_rule, logsource):
        """Build KQL where clauses from Sigma detection logic"""
        detection = sigma_rule.get('detection', {})
        conditions = []
        
        # Process each selection
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            if isinstance(value, dict):
                field_conditions = self.process_selection(value, logsource)
                if field_conditions:
                    # Group conditions with OR if multiple
                    if len(field_conditions) > 1:
                        conditions.append(f"({' or '.join(field_conditions)})")
                    else:
                        conditions.extend(field_conditions)
        
        # Combine with AND
        if conditions:
            return '| where ' + ' and '.join(conditions)
        return ''
    
    def process_selection(self, selection, logsource):
        """Process a selection dictionary into KQL conditions"""
        conditions = []
        
        for field, values in selection.items():
            # Handle field modifiers (e.g., field|endswith, field|contains)
            kql_field = self.map_field_to_kql(field, logsource)
            operator, kql_field = self.extract_operator(field, kql_field)
            
            if isinstance(values, list):
                # Multiple values - use 'in' or 'has_any'
                value_conditions = []
                for value in values:
                    value_conditions.append(self.build_condition(kql_field, operator, value))
                
                if len(value_conditions) > 1:
                    conditions.append(f"({' or '.join(value_conditions)})")
                else:
                    conditions.extend(value_conditions)
            else:
                # Single value
                conditions.append(self.build_condition(kql_field, operator, values))
        
        return conditions
    
    def map_field_to_kql(self, field, logsource):
        """Map Sigma field names to KQL field names"""
        # Remove modifiers
        base_field = field.split('|')[0]
        
        # Common field mappings
        field_map = {
            'Image': 'NewProcessName',
            'CommandLine': 'CommandLine',
            'ParentImage': 'ParentProcessName',
            'User': 'AccountName',
            'ComputerName': 'Computer',
            'TargetImage': 'TargetProcessName',
            'SourceImage': 'ProcessName',
            'EventID': 'EventID',
            'ServiceName': 'ServiceName',
            'TargetUserName': 'TargetUserName',
            'IpAddress': 'IpAddress'
        }
        
        return field_map.get(base_field, base_field)
    
    def extract_operator(self, field, kql_field):
        """Extract operator from field modifier"""
        if '|endswith' in field:
            return 'endswith', kql_field
        elif '|startswith' in field:
            return 'startswith', kql_field
        elif '|contains' in field:
            return 'contains', kql_field
        elif '|re' in field:
            return 'matches regex', kql_field
        else:
            return '==', kql_field
    
    def build_condition(self, field, operator, value):
        """Build a single KQL condition"""
        if operator == 'endswith':
            return f"{field} endswith '{value}'"
        elif operator == 'startswith':
            return f"{field} startswith '{value}'"
        elif operator == 'contains':
            return f"{field} contains '{value}'"
        elif operator == 'matches regex':
            return f"{field} matches regex @'{value}'"
        else:
            return f"{field} == '{value}'"
    
    def convert_all_rules(self):
        """Convert all Sigma rules in the directory"""
        print(f"Converting Sigma rules from: {self.rules_dir}")
        print(f"Output directory: {self.output_dir}")
        print("-" * 60)
        
        # Find all .yml files
        rule_files = list(self.rules_dir.glob('*.yml'))
        
        if not rule_files:
            print("No Sigma rules found!")
            return
        
        for rule_file in rule_files:
            self.conversion_stats['total'] += 1
            print(f"Processing: {rule_file.name}")
            
            # Load rule
            sigma_rule = self.load_sigma_rule(rule_file)
            if not sigma_rule:
                self.conversion_stats['failed'] += 1
                continue
            
            # Convert to KQL
            try:
                kql_query = self.convert_to_kql(sigma_rule, rule_file.stem)
                
                # Save KQL file
                output_file = self.output_dir / f"{rule_file.stem}.kql"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(kql_query)
                
                print(f"  ✓ Converted to: {output_file.name}")
                self.conversion_stats['success'] += 1
                
            except Exception as e:
                print(f"  ✗ Error converting: {e}")
                self.conversion_stats['failed'] += 1
        
        self.print_summary()
    
    def print_summary(self):
        """Print conversion summary"""
        print("\n" + "=" * 60)
        print("CONVERSION SUMMARY")
        print("=" * 60)
        print(f"Total rules:      {self.conversion_stats['total']}")
        print(f"Successful:       {self.conversion_stats['success']}")
        print(f"Failed:           {self.conversion_stats['failed']}")
        print(f"Success rate:     {(self.conversion_stats['success']/self.conversion_stats['total']*100):.1f}%")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Convert Sigma detection rules to KQL queries'
    )
    parser.add_argument(
        '--rules-dir',
        default='rules/sigma',
        help='Directory containing Sigma rules (default: rules/sigma)'
    )
    parser.add_argument(
        '--output-dir',
        default='converted/kql',
        help='Output directory for KQL queries (default: converted/kql)'
    )
    
    args = parser.parse_args()
    
    # Create converter and run
    converter = SigmaToKQLConverter(args.rules_dir, args.output_dir)
    converter.convert_all_rules()


if __name__ == '__main__':
    main()
