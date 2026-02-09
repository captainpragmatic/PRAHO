"""
Security Linter for PRAHO Platform API
Automated detection of security vulnerabilities in API endpoints.
🔒 Prevents customer enumeration and unauthorized data access.
"""

import ast
import re
from pathlib import Path


class SecurityViolation:
    """Represents a detected security violation"""
    
    def __init__(self, file_path: str, line_number: int, violation_type: str, message: str, severity: str = "HIGH"):
        self.file_path = file_path
        self.line_number = line_number
        self.violation_type = violation_type
        self.message = message
        self.severity = severity
    
    def __str__(self) -> str:
        return f"🚨 {self.severity}: {self.file_path}:{self.line_number} - {self.violation_type}: {self.message}"


class APISecurityLinter:
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
        self.violations: list[SecurityViolation] = []
        
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
            r'customer: Customer',  # Function parameter indicates customer authentication
            r'def.*customer: Customer',  # Function definition with customer parameter
        ]
    
    def lint_file(self, file_path: Path) -> None:
        """Lint a single Python file for security violations"""
        
        if file_path.suffix != '.py':
            return
        
        try:
            with open(file_path, encoding='utf-8') as f:
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
    
    def _check_ast_violations(self, file_path: Path, tree: ast.AST, content: str, lines: list[str]) -> None:
        """Check for violations using AST analysis"""
        
        class APIVisitor(ast.NodeVisitor):
            def __init__(self, linter, file_path, lines) -> None:
                self.linter = linter
                self.file_path = file_path
                self.lines = lines
                self.in_api_view = False
                self.current_function = None
                self.http_methods = set()
            
            def visit_FunctionDef(self, node) -> None:
                self.current_function = node.name
                
                # Check for @api_view decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and (hasattr(decorator.func, 'id') and 
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
            
            def _check_function_violations(self, node) -> None:
                """Check specific function for security violations"""

                function_source = ast.get_source_segment(content, node)
                if not function_source:
                    return

                # Check for customer data access patterns
                has_customer_data = any(
                    re.search(pattern, function_source)
                    for pattern in self.linter.customer_data_patterns
                )

                has_proper_auth = any(
                    re.search(pattern, function_source)
                    for pattern in self.linter.auth_patterns
                )

                # Check if ANY endpoint (GET, POST, etc) accesses customer data without proper auth
                if has_customer_data and not has_proper_auth:
                    # Determine severity based on HTTP method
                    severity = "CRITICAL" if 'GET' in self.http_methods else "HIGH"
                    method_list = ', '.join(sorted(self.http_methods)) if self.http_methods else 'UNKNOWN'

                    self.linter.violations.append(SecurityViolation(
                        str(self.file_path),
                        node.lineno,
                        "CUSTOMER_ENUMERATION",
                        f"{method_list} endpoint '{self.current_function}' accesses customer data without proper authentication",
                        severity
                    ))

                # Check for customer_id in query parameters (GET specific)
                if 'GET' in self.http_methods and re.search(r'request\.GET\.get.*customer_id', function_source):
                        self.linter.violations.append(SecurityViolation(
                            str(self.file_path),
                            node.lineno,
                            "CUSTOMER_ID_IN_QUERY",
                            f"GET endpoint '{self.current_function}' accepts customer_id in query string",
                            "HIGH"
                        ))
        
        visitor = APIVisitor(self, file_path, lines)
        visitor.visit(tree)
    
    def _check_regex_violations(self, file_path: Path, lines: list[str]) -> None:
        """Check for violations using regex patterns (fallback when AST fails)"""

        current_methods = set()
        in_api_endpoint = False
        current_function = None
        function_lines = []

        for i, line in enumerate(lines, 1):
            # Track API endpoints with any HTTP methods
            api_view_match = re.search(r'@api_view\(\[(.+?)\]\)', line)
            if api_view_match:
                methods_str = api_view_match.group(1)
                # Extract methods from strings like "'GET', 'POST'" or '"GET", "POST"'
                method_matches = re.findall(r'["\']([A-Z]+)["\']', methods_str)
                current_methods = set(method_matches)
                in_api_endpoint = True
                function_lines = [i]
                continue

            # Track function definitions
            if line.strip().startswith('def ') and in_api_endpoint:
                current_function = re.search(r'def\s+(\w+)', line)
                current_function = current_function.group(1) if current_function else 'unknown'

            # Check for violations in API endpoints
            if in_api_endpoint and current_function:
                # Check for customer data access patterns
                for pattern in self.customer_data_patterns:
                    if re.search(pattern, line):
                        # Check if proper authentication is present in the function
                        has_auth = any(
                            re.search(auth_pattern, '\n'.join(lines[max(0, i-10):i+10]))
                            for auth_pattern in self.auth_patterns
                        )

                        if not has_auth:
                            severity = "CRITICAL" if 'GET' in current_methods else "HIGH"
                            method_list = ', '.join(sorted(current_methods)) if current_methods else 'UNKNOWN'

                            self.violations.append(SecurityViolation(
                                str(file_path),
                                i,
                                "CUSTOMER_ENUMERATION",
                                f"{method_list} endpoint '{current_function}' may access customer data without proper authentication: {pattern}",
                                severity
                            ))

                # Check for query string customer_id (GET specific)
                if 'GET' in current_methods and re.search(r'request\.GET\.get.*customer_id', line):
                    self.violations.append(SecurityViolation(
                        str(file_path),
                        i,
                        "CUSTOMER_ID_IN_QUERY",
                        "Customer ID found in GET query parameters",
                        "HIGH"
                    ))

            # Reset when we reach next function or decorator
            if line.strip().startswith('def ') and not in_api_endpoint:
                pass
            elif line.strip().startswith('@') and in_api_endpoint and len(function_lines) > 10:
                in_api_endpoint = False
                current_methods = set()
                function_lines = []
    
    def lint_directory(self, directory: Path | None = None) -> None:
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
                report.extend(f"  • {violation}" for violation in by_severity[severity])
                report.append("")
        
        # Summary
        report.append("📋 SUMMARY:")
        report.append(f"  • Total violations: {len(self.violations)}")
        report.append(f"  • Critical: {len(by_severity.get('CRITICAL', []))}")
        report.append(f"  • High: {len(by_severity.get('HIGH', []))}")
        report.append(f"  • Files affected: {len({v.file_path for v in self.violations})}")
        
        return "\n".join(report)


def main() -> int:
    """Run security linter from command line"""
    platform_root = Path(__file__).parent.parent.parent
    api_root = platform_root / "apps" / "api"
    
    print("🔒 PRAHO Platform API Security Linter")
    print(f"📂 Scanning: {api_root}")
    print("")
    
    linter = APISecurityLinter(str(api_root))
    linter.lint_directory()
    
    report = linter.generate_report()
    print(report)
    
    if linter.violations:
        critical_count = len([v for v in linter.violations if v.severity == 'CRITICAL'])
        if critical_count > 0:
            print("\n❌ CRITICAL violations found. Build should fail.")
            return 1
        else:
            print("\n⚠️ Security violations found but no critical issues.")
            return 2
    else:
        print("\n✅ No security violations detected.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
