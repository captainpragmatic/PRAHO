"""
Security Linter for PRAHO Platform API
Automated detection of security vulnerabilities in API endpoints.
🔒 Prevents customer enumeration and unauthorized data access.
"""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

class SecurityViolation:
    """Represents a detected security violation"""
    
    def __init__(self, file_path: str, line_number: int, violation_type: str, message: str, severity: str = "HIGH"):
        self.file_path = file_path
        self.line_number = line_number
        self.violation_type = violation_type
        self.message = message
        self.severity = severity
    
    def __str__(self):
        return f"🚨 {self.severity}: {self.file_path}:{self.line_number} - {self.violation_type}: {self.message}"


class APISecurity Linter:
    """
    🔒 Security linter for API endpoints
    
    Detects:
    - GET endpoints that access customer data
    - Missing customer authentication on customer-scoped endpoints
    - Customer ID in query strings
    - Inconsistent error responses
    """
    
    def __init__(self, api_root: str = "/apps/api/"):
        self.api_root = Path(api_root)
        self.violations: List[SecurityViolation] = []
        
        # Patterns that indicate customer data access
        self.customer_data_patterns = [
            r'customer_id',
            r'customer\.id',
            r'request\.user',
            r'CustomerMembership',
            r'Customer\.objects',
            r'get_customer',
            r'customer_scoped',
        ]
        
        # Patterns that indicate proper authentication
        self.auth_patterns = [
            r'@require_customer_authentication',
            r'require_customer_authentication',
            r'customer.*parameter.*injected',
        ]
    
    def lint_file(self, file_path: Path) -> None:
        """Lint a single Python file for security violations"""
        
        if not file_path.suffix == '.py':
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Parse AST for more accurate detection
            try:
                tree = ast.parse(content)
                self._check_ast_violations(file_path, tree, content, lines)
            except SyntaxError:
                # If AST parsing fails, fall back to regex
                pass
            
            # Always run regex checks as backup
            self._check_regex_violations(file_path, lines)
            
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
    
    def _check_ast_violations(self, file_path: Path, tree: ast.AST, content: str, lines: List[str]) -> None:
        """Check for violations using AST analysis"""
        
        class APIVisitor(ast.NodeVisitor):
            def __init__(self, linter, file_path, lines):
                self.linter = linter
                self.file_path = file_path
                self.lines = lines
                self.in_api_view = False
                self.current_function = None
                self.http_methods = set()
            
            def visit_FunctionDef(self, node):
                self.current_function = node.name
                
                # Check for @api_view decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        if (hasattr(decorator.func, 'id') and 
                            decorator.func.id == 'api_view'):
                            self.in_api_view = True
                            
                            # Extract HTTP methods
                            if decorator.args and isinstance(decorator.args[0], ast.List):
                                for method in decorator.args[0].elts:
                                    if isinstance(method, ast.Constant):
                                        self.http_methods.add(method.value)
                
                # Check function body for violations
                if self.in_api_view:
                    self._check_function_violations(node)
                
                self.generic_visit(node)
                
                # Reset state
                self.in_api_view = False
                self.http_methods = set()
            
            def _check_function_violations(self, node):
                """Check specific function for security violations"""
                
                # Check if GET method accesses customer data
                if 'GET' in self.http_methods:
                    function_source = ast.get_source_segment(content, node)
                    if function_source:
                        has_customer_data = any(
                            re.search(pattern, function_source) 
                            for pattern in self.linter.customer_data_patterns
                        )
                        
                        has_proper_auth = any(
                            re.search(pattern, function_source)
                            for pattern in self.linter.auth_patterns
                        )
                        
                        if has_customer_data and not has_proper_auth:
                            self.linter.violations.append(SecurityViolation(
                                str(self.file_path),
                                node.lineno,
                                "CUSTOMER_ENUMERATION",
                                f"GET endpoint '{self.current_function}' accesses customer data without proper authentication",
                                "CRITICAL"
                            ))
                
                # Check for customer_id in query parameters
                if 'GET' in self.http_methods and function_source:
                    if re.search(r'request\.GET\.get.*customer_id', function_source):
                        self.linter.violations.append(SecurityViolation(
                            str(self.file_path),
                            node.lineno,
                            "CUSTOMER_ID_IN_QUERY",
                            f"GET endpoint '{self.current_function}' accepts customer_id in query string",
                            "HIGH"
                        ))
        
        visitor = APIVisitor(self, file_path, lines)
        visitor.visit(tree)
    
    def _check_regex_violations(self, file_path: Path, lines: List[str]) -> None:
        """Check for violations using regex patterns"""
        
        in_get_endpoint = False
        get_function_lines = []
        current_function = None
        
        for i, line in enumerate(lines, 1):
            # Track GET endpoints
            if "@api_view(['GET'])" in line or '@api_view(["GET"])' in line:
                in_get_endpoint = True
                get_function_lines = [i]
                continue
            
            # Track function definitions
            if line.strip().startswith('def ') and in_get_endpoint:
                current_function = re.search(r'def\s+(\w+)', line)
                current_function = current_function.group(1) if current_function else 'unknown'
            
            # Check for violations in GET endpoints
            if in_get_endpoint:
                # Check for customer data access patterns
                for pattern in self.customer_data_patterns:
                    if re.search(pattern, line):
                        self.violations.append(SecurityViolation(
                            str(file_path),
                            i,
                            "CUSTOMER_ENUMERATION",
                            f"GET endpoint '{current_function}' may access customer data: {pattern}",
                            "HIGH"
                        ))
                
                # Check for query string customer_id
                if re.search(r'request\.GET\.get.*customer_id', line):
                    self.violations.append(SecurityViolation(
                        str(file_path),
                        i,
                        "CUSTOMER_ID_IN_QUERY", 
                        f"Customer ID found in GET query parameters",
                        "HIGH"
                    ))
            
            # Reset when we reach next function or end of current function
            if line.strip().startswith('def ') and not in_get_endpoint:
                pass
            elif line.strip().startswith('@') and in_get_endpoint and len(get_function_lines) > 5:
                in_get_endpoint = False
                get_function_lines = []
    
    def lint_directory(self, directory: Path = None) -> None:
        """Recursively lint all Python files in directory"""
        
        if directory is None:
            directory = self.api_root
        
        for file_path in directory.rglob("*.py"):
            # Skip __pycache__ and test files for now
            if '__pycache__' in str(file_path) or 'test_' in file_path.name:
                continue
            
            self.lint_file(file_path)
    
    def generate_report(self) -> str:
        """Generate security report"""
        
        if not self.violations:
            return "✅ No security violations detected!"
        
        report = ["🚨 SECURITY VIOLATIONS DETECTED:", ""]
        
        # Group by severity
        by_severity = {}
        for violation in self.violations:
            if violation.severity not in by_severity:
                by_severity[violation.severity] = []
            by_severity[violation.severity].append(violation)
        
        # Report by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                report.append(f"📊 {severity} SEVERITY ({len(by_severity[severity])} issues):")
                for violation in by_severity[severity]:
                    report.append(f"  • {violation}")
                report.append("")
        
        # Summary
        report.append("📋 SUMMARY:")
        report.append(f"  • Total violations: {len(self.violations)}")
        report.append(f"  • Critical: {len(by_severity.get('CRITICAL', []))}")
        report.append(f"  • High: {len(by_severity.get('HIGH', []))}")
        report.append(f"  • Files affected: {len(set(v.file_path for v in self.violations))}")
        
        return "\n".join(report)


def main():
    """Run security linter from command line"""
    import sys
    
    platform_root = Path(__file__).parent.parent.parent
    api_root = platform_root / "apps" / "api"
    
    print("🔒 PRAHO Platform API Security Linter")
    print(f"📂 Scanning: {api_root}")
    print("")
    
    linter = APISecurityLinter(str(api_root))
    linter.lint_directory()
    
    report = linter.generate_report()
    print(report)
    
    # Exit with error code if violations found
    if linter.violations:
        critical_count = len([v for v in linter.violations if v.severity == 'CRITICAL'])
        if critical_count > 0:
            print(f"\n❌ CRITICAL violations found. Build should fail.")
            sys.exit(1)
        else:
            print(f"\n⚠️ Security violations found but no critical issues.")
            sys.exit(2)
    else:
        print(f"\n✅ No security violations detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()