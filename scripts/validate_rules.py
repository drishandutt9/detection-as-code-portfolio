#!/usr/bin/env python3
"""
Sigma Rule Validator
Validates Sigma rules for syntax, completeness, and best practices
"""

import yaml
import sys
from pathlib import Path


class SigmaRuleValidator:
    """Validates Sigma detection rules"""
    
    REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'logsource', 'detection']
    RECOMMENDED_FIELDS = ['author', 'date', 'references', 'tags', 'level', 'falsepositives']
    VALID_STATUSES = ['stable', 'test', 'experimental', 'deprecated']
    VALID_LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
    
    def __init__(self):
        self.validation_results = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }
    
    def validate_rule(self, rule_path):
        """Validate a single Sigma rule"""
        errors = []
        warnings = []
        
        print(f"\nValidating: {rule_path.name}")
        print("-" * 50)
        
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {e}")
            return errors, warnings
        except Exception as e:
            errors.append(f"File reading error: {e}")
            return errors, warnings
        
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in rule:
                errors.append(f"Missing required field: {field}")
        
        # Check recommended fields
        for field in self.RECOMMENDED_FIELDS:
            if field not in rule:
                warnings.append(f"Missing recommended field: {field}")
        
        # Validate status
        if 'status' in rule and rule['status'] not in self.VALID_STATUSES:
            errors.append(f"Invalid status: {rule['status']}. Must be one of {self.VALID_STATUSES}")
        
        # Validate level
        if 'level' in rule and rule['level'] not in self.VALID_LEVELS:
            errors.append(f"Invalid level: {rule['level']}. Must be one of {self.VALID_LEVELS}")
        
        # Validate ID format (basic UUID check)
        if 'id' in rule:
            rule_id = rule['id']
            if not isinstance(rule_id, str) or len(rule_id) != 36:
                warnings.append(f"ID should be a UUID format (e.g., 12345678-1234-1234-1234-123456789abc)")
        
        # Validate detection section
        if 'detection' in rule:
            detection_errors = self.validate_detection(rule['detection'])
            errors.extend(detection_errors)
        
        # Validate logsource
        if 'logsource' in rule:
            logsource_warnings = self.validate_logsource(rule['logsource'])
            warnings.extend(logsource_warnings)
        
        # Check for MITRE ATT&CK tags
        if 'tags' in rule:
            has_attack_tag = any('attack.' in str(tag) for tag in rule['tags'])
            if not has_attack_tag:
                warnings.append("No MITRE ATT&CK tags found (recommended)")
        
        return errors, warnings
    
    def validate_detection(self, detection):
        """Validate detection logic"""
        errors = []
        
        if not isinstance(detection, dict):
            errors.append("Detection must be a dictionary")
            return errors
        
        # Check for condition
        if 'condition' not in detection:
            errors.append("Detection missing 'condition' field")
        
        # Check for at least one selection
        selections = [k for k in detection.keys() if k.startswith('selection')]
        if not selections:
            errors.append("Detection should have at least one 'selection' field")
        
        return errors
    
    def validate_logsource(self, logsource):
        """Validate logsource section"""
        warnings = []
        
        if not isinstance(logsource, dict):
            warnings.append("Logsource should be a dictionary")
            return warnings
        
        # Check for common logsource fields
        common_fields = ['category', 'product', 'service']
        has_field = any(field in logsource for field in common_fields)
        
        if not has_field:
            warnings.append("Logsource should have at least one of: category, product, service")
        
        return warnings
    
    def print_results(self, rule_name, errors, warnings):
        """Print validation results for a rule"""
        if errors:
            print("❌ FAILED")
            for error in errors:
                print(f"  ERROR: {error}")
            self.validation_results['failed'] += 1
        else:
            print("✅ PASSED")
            self.validation_results['passed'] += 1
        
        if warnings:
            print("⚠️  WARNINGS:")
            for warning in warnings:
                print(f"  {warning}")
            self.validation_results['warnings'] += len(warnings)
    
    def validate_directory(self, rules_dir):
        """Validate all rules in a directory"""
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            print(f"Error: Directory not found: {rules_dir}")
            sys.exit(1)
        
        print("=" * 60)
        print("SIGMA RULE VALIDATION")
        print("=" * 60)
        
        rule_files = list(rules_path.glob('*.yml'))
        
        if not rule_files:
            print("No Sigma rules found in directory!")
            sys.exit(1)
        
        for rule_file in rule_files:
            self.validation_results['total'] += 1
            errors, warnings = self.validate_rule(rule_file)
            self.print_results(rule_file.name, errors, warnings)
        
        self.print_summary()
    
    def print_summary(self):
        """Print overall validation summary"""
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Total rules:      {self.validation_results['total']}")
        print(f"Passed:           {self.validation_results['passed']}")
        print(f"Failed:           {self.validation_results['failed']}")
        print(f"Total warnings:   {self.validation_results['warnings']}")
        
        if self.validation_results['failed'] == 0:
            print("\n✅ All rules passed validation!")
        else:
            print(f"\n❌ {self.validation_results['failed']} rule(s) failed validation")
        
        print("=" * 60)
        
        # Exit with error code if any rules failed
        if self.validation_results['failed'] > 0:
            sys.exit(1)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Validate Sigma detection rules'
    )
    parser.add_argument(
        '--rules-dir',
        default='rules/sigma',
        help='Directory containing Sigma rules (default: rules/sigma)'
    )
    
    args = parser.parse_args()
    
    validator = SigmaRuleValidator()
    validator.validate_directory(args.rules_dir)


if __name__ == '__main__':
    main()
