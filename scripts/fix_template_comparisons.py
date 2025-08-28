#!/usr/bin/env python3
"""
🔧 Django Template Syntax Fixer
Automatically fix template syntax issues in Django templates.

This script prevents TemplateSyntaxError by fixing:
- Comparison operator spacing (==, !=, <, >, <=, >=)  
- Filter argument spacing (|filter : arg -> |filter:arg)
"""

import re
import time
from pathlib import Path

# ===============================================================================
# CONFIGURATION
# ===============================================================================

TEMPLATE_DIRS = [
    "templates",
    "apps/*/templates",
]

COMPARISON_OPERATORS = [
    r'(\w+)(==)(\w+)',  # var==value -> var == value
    r'(\w+)(!=)(\w+)',  # var!=value -> var != value
    r'(\w+)(<=)(\w+)',  # var<=value -> var <= value
    r'(\w+)(>=)(\w+)',  # var>=value -> var >= value
    # Only match < and > if they're clearly within Django template tags
    r'({%\s+if\s+[^%]*\w+)(<)(\w+[^%]*%})',   # {% if var<value %}
    r'({%\s+if\s+[^%]*\w+)(>)(\w+[^%]*%})',   # {% if var>value %}
]

# Filter argument patterns (spaces around : in filter arguments)
FILTER_PATTERNS = [
    r'(\|\s*\w+\s*):\s+(\w+)',  # |filter : arg -> |filter:arg
    r'(\|\s*\w+)\s+:\s*(\w+)',  # |filter : arg -> |filter:arg
]

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def check_if_recently_modified(file_path: Path) -> bool:
    """Check if file was modified in the last 5 minutes (could be IDE auto-formatting)"""
    try:
        mtime = file_path.stat().st_mtime
        current_time = time.time()
        return (current_time - mtime) < 300  # 5 minutes
    except OSError:
        return False

def detect_potential_auto_formatting(changes: list[str], file_path: Path) -> list[str]:
    """Detect if issues might be caused by IDE auto-formatting"""
    warnings = []

    if check_if_recently_modified(file_path):
        warnings.append("⚠️  File modified recently - could be IDE auto-formatting")

    # Check for multiple comparison operators fixed (common in auto-formatting)
    operator_count = len([c for c in changes if any(op in c for op in ['==', '!=', '<=', '>=', '<', '>'])])
    if operator_count > 2:
        warnings.append("⚠️  Multiple operators affected - check IDE settings")

    return warnings

def find_template_files(base_dir: Path) -> list[Path]:
    """Find all Django template files"""
    template_files: list[Path] = []

    for pattern in TEMPLATE_DIRS:
        if "*" in pattern:
            # Handle glob patterns like apps/*/templates
            for match_dir in base_dir.glob(pattern):
                if match_dir.is_dir():
                    template_files.extend(match_dir.glob("**/*.html"))
        else:
            # Handle direct paths like templates
            template_dir = base_dir / pattern
            if template_dir.is_dir():
                template_files.extend(template_dir.glob("**/*.html"))

    return sorted(set(template_files))

def fix_template_syntax(content: str) -> tuple[str, list[str]]:
    """Fix comparison operators and filter syntax in template content"""
    changes = []
    fixed_content = content

    # Fix comparison operators
    for pattern in COMPARISON_OPERATORS:
        matches = re.finditer(pattern, fixed_content)

        for match in matches:
            old_text = match.group(0)
            var, op, value = match.groups()
            new_text = f"{var} {op} {value}"

            if old_text != new_text:
                changes.append(f"  {old_text} → {new_text}")
                fixed_content = fixed_content.replace(old_text, new_text)

    # Fix filter argument spacing
    for pattern in FILTER_PATTERNS:
        matches = re.finditer(pattern, fixed_content)

        for match in matches:
            old_text = match.group(0)
            filter_part, arg_part = match.groups()
            new_text = f"{filter_part.rstrip()}:{arg_part.lstrip()}"

            if old_text != new_text:
                changes.append(f"  {old_text} → {new_text}")
                fixed_content = fixed_content.replace(old_text, new_text)

    return fixed_content, changes

def process_template_file(file_path: Path) -> tuple[bool, list[str]]:
    """Process a single template file"""
    try:
        original_content = file_path.read_text(encoding='utf-8')
        fixed_content, changes = fix_template_syntax(original_content)

        if changes:
            # Write fixed content directly
            file_path.write_text(fixed_content, encoding='utf-8')

            return True, changes

        return False, []

    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return False, []

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

def main() -> None:
    """Main execution function"""

    print("🔧 Django Template Comparison Operator Fixer")
    print("=" * 50)

    # Find project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    print(f"📁 Project root: {project_root}")

    # Find all template files
    template_files = find_template_files(project_root)

    if not template_files:
        print("❌ No template files found!")
        return

    print(f"📋 Found {len(template_files)} template files")
    print()

    # Process files
    fixed_files = 0
    total_changes = 0

    for file_path in template_files:
        relative_path = file_path.relative_to(project_root)
        print(f"🔍 Processing: {relative_path}")

        modified, changes = process_template_file(file_path)

        if modified:
            fixed_files += 1
            total_changes += len(changes)
            print(f"  ✅ Fixed {len(changes)} comparison operators")
            for change in changes:
                print(f"    {change}")
        else:
            print("  ✓ No changes needed")

        print()

    # Summary
    print("=" * 50)
    print("📊 SUMMARY")
    print("=" * 50)
    print(f"✅ Files processed: {len(template_files)}")
    print(f"🔧 Files fixed: {fixed_files}")
    print(f"🔄 Total changes: {total_changes}")

    if fixed_files > 0:
        print()
        print("🧪 Run tests to verify the fixes work correctly")

def check_only() -> int:
    """Check for issues without fixing them"""

    print("🔍 Django Template Syntax Checker")
    print("=" * 50)

    # Find project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Find all template files
    template_files = find_template_files(project_root)

    issues_found = 0
    files_with_issues = 0

    for file_path in template_files:
        relative_path = file_path.relative_to(project_root)

        try:
            content = file_path.read_text(encoding='utf-8')
            _, changes = fix_template_syntax(content)

            if changes:
                if files_with_issues == 0:
                    print("❌ Issues found in the following files:")
                    print()

                files_with_issues += 1
                issues_found += len(changes)

                print(f"📄 {relative_path}")
                for change in changes:
                    print(f"  {change}")

                # Check for potential auto-formatting issues
                warnings = detect_potential_auto_formatting(changes, file_path)
                for warning in warnings:
                    print(f"  {warning}")

                print()

        except Exception as e:
            print(f"❌ Error checking {relative_path}: {e}")

    if files_with_issues == 0:
        print("✅ No template syntax issues found!")
        return 0
    else:
        print("=" * 50)
        print(f"❌ Found {issues_found} issues in {files_with_issues} files")
        print("🔧 Run 'python scripts/fix_template_comparisons.py' to fix them")
        return 1

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        exit_code = check_only()
        sys.exit(exit_code)
    else:
        main()
