#!/usr/bin/env python3
"""
🚫 Type Ignore Prevention Script for PRAHO Platform

This script prevents new # type: ignore comments from being added to maintain
type safety progress during gradual typing rollout.

Usage:
    python scripts/prevent_type_ignore.py [file1.py file2.py ...]
    python scripts/prevent_type_ignore.py --check-all
    python scripts/prevent_type_ignore.py --allow-legacy
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Any


class TypeIgnoreChecker:
    """Checks for and prevents new # type: ignore comments."""
    
    def __init__(self, allow_legacy: bool = False, strict_mode: bool = True):
        self.allow_legacy = allow_legacy
        self.strict_mode = strict_mode
        
        # Pattern to match type ignore comments
        self.type_ignore_pattern = re.compile(
            r'#\s*type:\s*ignore\b',
            re.IGNORECASE
        )
        
        # Files where type ignore is still acceptable (legacy)
        self.legacy_allowlist = {
            'apps/integrations/',  # Complex third-party integrations
            'apps/provisioning/',  # Infrastructure code
            'apps/domains/',       # Multi-registrar complexity
            'tests/',              # Test code can be more flexible
        }
        
        # Always strict - no type ignore allowed
        self.strict_modules = {
            'apps/common/types.py',
            'apps/common/validators.py', 
            'apps/common/utils.py',
            'apps/audit/services.py',
            'apps/billing/services.py',
            'apps/users/services.py',
        }
    
    def is_legacy_file(self, file_path: str) -> bool:
        """Check if file is in legacy allowlist."""
        if not self.allow_legacy:
            return False
            
        path_str = str(file_path)
        return any(legacy in path_str for legacy in self.legacy_allowlist)
    
    def is_strict_file(self, file_path: str) -> bool:
        """Check if file requires strict type safety."""
        path_str = str(file_path)
        return any(strict in path_str for strict in self.strict_modules)
    
    def should_skip_file(self, file_path: str) -> bool:
        """Determine if file should be skipped from checking."""
        path_str = str(file_path)
        
        # Skip migrations
        if 'migrations/' in path_str:
            return True
        
        # Skip non-Python files
        if not file_path.endswith('.py'):
            return True
        
        # Skip if file doesn't exist
        if not Path(file_path).exists():
            return True
            
        return False
    
    def check_file_for_type_ignore(self, file_path: str) -> tuple[bool, list[dict[str, Any]]]:
        """
        Check a single file for type ignore comments.
        
        Returns:
            (has_violations, violations_list)
        """
        if self.should_skip_file(file_path):
            return False, []
        
        violations = []
        
        try:
            with open(file_path, encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"❌ Error reading {file_path}: {e}")
            return False, []
        
        for line_no, line in enumerate(lines, 1):
            match = self.type_ignore_pattern.search(line)
            if match:
                violation = {
                    'file': file_path,
                    'line': line_no,
                    'content': line.strip(),
                    'position': match.start(),
                    'is_legacy': self.is_legacy_file(file_path),
                    'is_strict': self.is_strict_file(file_path)
                }
                violations.append(violation)
        
        return len(violations) > 0, violations
    
    def format_violation_message(self, violations: list[dict[str, Any]]) -> str:
        """Format violation messages for output."""
        if not violations:
            return ""
        
        message_parts = []
        
        # Group by file
        files_with_violations = {}
        for violation in violations:
            file_path = violation['file']
            if file_path not in files_with_violations:
                files_with_violations[file_path] = []
            files_with_violations[file_path].append(violation)
        
        for file_path, file_violations in files_with_violations.items():
            message_parts.append(f"\n📁 {file_path}:")
            
            for v in file_violations:
                icon = "🚨" if v['is_strict'] else ("⚠️" if not v['is_legacy'] else "ℹ️")
                message_parts.append(f"  {icon} Line {v['line']}: {v['content']}")
                
                if v['is_strict']:
                    message_parts.append("     🚨 STRICT MODULE: # type: ignore not allowed")
                elif not v['is_legacy']:
                    message_parts.append("     ⚠️  Consider fixing type issues instead of ignoring")
        
        return '\n'.join(message_parts)
    
    def check_files(self, file_paths: list[str]) -> tuple[bool, str]:
        """
        Check multiple files for type ignore violations.
        
        Returns:
            (has_violations, formatted_message)
        """
        all_violations = []
        
        for file_path in file_paths:
            has_violations, violations = self.check_file_for_type_ignore(file_path)
            if has_violations:
                all_violations.extend(violations)
        
        # Determine if we should fail based on violations
        should_fail = False
        blocking_violations = []
        
        for violation in all_violations:
            # Always fail for strict modules
            if violation['is_strict'] or self.strict_mode and not violation['is_legacy']:
                should_fail = True
                blocking_violations.append(violation)
        
        # Format message
        if all_violations:
            message = "🚫 Type ignore comments detected:"
            message += self.format_violation_message(all_violations)
            
            if should_fail:
                message += "\n\n💡 To fix type issues instead of ignoring them:"
                message += "\n  • Run: mypy --config-file=pyproject.toml <file>"
                message += "\n  • Add proper type annotations"
                message += "\n  • Use Union types for mixed types"
                message += "\n  • Consider cast() for unavoidable cases"
                
                if not self.strict_mode:
                    message += "\n  • Use --allow-legacy flag for transition period"
            else:
                message += "\n\n✅ All violations are in legacy files (informational only)"
        else:
            message = "✅ No type ignore comments found"
        
        return should_fail, message


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Check for new # type: ignore comments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Check specific files (pre-commit usage)
    python scripts/prevent_type_ignore.py file1.py file2.py
    
    # Check all Python files in apps/
    python scripts/prevent_type_ignore.py --check-all
    
    # Allow legacy files during transition
    python scripts/prevent_type_ignore.py --allow-legacy file.py
        """
    )
    parser.add_argument(
        'files', 
        nargs='*', 
        help='Python files to check'
    )
    parser.add_argument(
        '--check-all', 
        action='store_true',
        help='Check all Python files in apps/'
    )
    parser.add_argument(
        '--allow-legacy',
        action='store_true', 
        help='Allow type ignore in legacy modules during transition'
    )
    parser.add_argument(
        '--no-strict',
        action='store_true',
        help='Disable strict mode (allow type ignore in non-legacy files)'
    )
    
    args = parser.parse_args()
    
    # Determine files to check
    if args.check_all:
        apps_dir = Path('apps')
        if not apps_dir.exists():
            print("❌ apps/ directory not found")
            return 1
        
        python_files = list(apps_dir.rglob('*.py'))
        files_to_check = [str(f) for f in python_files]
    else:
        files_to_check = args.files
    
    if not files_to_check:
        print("ℹ️  No files to check")
        return 0
    
    # Initialize checker
    checker = TypeIgnoreChecker(
        allow_legacy=args.allow_legacy,
        strict_mode=not args.no_strict
    )
    
    print("🔍 PRAHO Platform - Type Ignore Prevention")
    print(f"📋 Checking {len(files_to_check)} files...")
    print(f"⚙️  Mode: {'Legacy allowed' if args.allow_legacy else 'Strict'}")
    
    # Check files
    has_violations, message = checker.check_files(files_to_check)
    
    print(message)
    
    return 1 if has_violations else 0


if __name__ == "__main__":
    sys.exit(main())
