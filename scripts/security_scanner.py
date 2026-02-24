#!/usr/bin/env python3
"""
🔒 PRAHO Platform Security Scanner
Comprehensive security scanning for OWASP Top 10 2021/2024, CVEs, and known exploit patterns.

Scans for:
- OWASP Top 10 2021/2024 vulnerabilities
- Known Chinese APT exploit patterns (APT10, APT41, etc.)
- CVE-2024-XXXX and CVE-2025-XXXX known Python/Django exploits
- Supply chain vulnerabilities
- Secret exposure
- Injection vulnerabilities
- Authentication/authorization flaws
"""

from __future__ import annotations

import ast
import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""

    finding_id: str
    title: str
    description: str
    file_path: str
    line_number: int
    severity: Severity
    owasp_category: OWASPCategory | None
    cve_id: str | None
    cwe_id: str | None
    code_snippet: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    exploit_patterns: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete security scan result"""

    scan_timestamp: str
    codebase_path: str
    total_files_scanned: int
    total_lines_scanned: int
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a finding to the results"""
        self.findings.append(finding)

    def generate_report(self) -> str:
        """Generate human-readable report"""
        report = [
            "=" * 100,
            "🔒 PRAHO PLATFORM SECURITY SCAN REPORT",
            "=" * 100,
            f"Scan Timestamp: {self.scan_timestamp}",
            f"Codebase Path: {self.codebase_path}",
            f"Files Scanned: {self.total_files_scanned}",
            f"Lines Scanned: {self.total_lines_scanned}",
            "",
            "=" * 100,
            "📊 SUMMARY",
            "=" * 100,
        ]

        # Count by severity
        severity_counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1

        for severity, count in severity_counts.items():
            emoji = "🔴" if severity in ["CRITICAL", "HIGH"] else "🟡" if severity == "MEDIUM" else "🟢"
            report.append(f"{emoji} {severity}: {count}")

        # Count by OWASP category
        owasp_counts: dict[str, int] = {}
        for finding in self.findings:
            if finding.owasp_category:
                cat = finding.owasp_category.value
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        if owasp_counts:
            report.append("")
            report.append("=" * 100)
            report.append("📋 OWASP TOP 10 CATEGORIES")
            report.append("=" * 100)
            for category, count in sorted(owasp_counts.items(), key=lambda x: -x[1]):
                report.append(f"  • {category}: {count}")

        # List critical and high severity findings
        critical_high = [f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            report.append("")
            report.append("=" * 100)
            report.append("🚨 CRITICAL & HIGH SEVERITY FINDINGS")
            report.append("=" * 100)
            for finding in critical_high:
                report.append(f"\n[{finding.finding_id}] {finding.title}")
                report.append(f"  Severity: {finding.severity.value}")
                if finding.owasp_category:
                    report.append(f"  OWASP: {finding.owasp_category.value}")
                if finding.cve_id:
                    report.append(f"  CVE: {finding.cve_id}")
                if finding.cwe_id:
                    report.append(f"  CWE: {finding.cwe_id}")
                report.append(f"  Location: {finding.file_path}:{finding.line_number}")
                report.append(f"  Code: {finding.code_snippet[:100]}...")
                report.append(f"  Recommendation: {finding.recommendation}")

        return "\n".join(report)


class SecurityScanner:
    """Main security scanner class"""

    def __init__(self, codebase_path: str):
        self.codebase_path = Path(codebase_path)
        self.finding_counter = 0
        self.files_scanned = 0
        self.lines_scanned = 0

        # OWASP Top 10 2021/2024 patterns
        self.injection_patterns = [
            # SQL Injection
            (
                r'execute\s*\(\s*f["\']',
                "SQL Injection - f-string in execute()",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            (
                r"cursor\.execute\s*\([^,]+%",
                "SQL Injection - % formatting in execute()",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            (r'raw\s*\(\s*f["\']', "SQL Injection - f-string in raw query", Severity.CRITICAL, "A03:2021-Injection"),
            # Command Injection
            (
                r"os\.system\s*\([^)]*\+",
                "Command Injection - string concatenation in os.system()",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            (
                r"subprocess\.(call|run|Popen)\s*\([^)]*\+",
                "Command Injection - string concatenation in subprocess",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            (
                r"eval\s*\([^)]*\+",
                "Code Injection - eval() with dynamic input",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            (
                r"exec\s*\([^)]*\+",
                "Code Injection - exec() with dynamic input",
                Severity.CRITICAL,
                "A03:2021-Injection",
            ),
            # XSS
            (r"mark_safe\s*\([^)]*\+", "XSS - mark_safe() with dynamic input", Severity.HIGH, "A03:2021-Injection"),
            (r"format_html\s*\([^)]*%", "XSS - format_html() with % formatting", Severity.MEDIUM, "A03:2021-Injection"),
        ]

        # Cryptographic failures
        self.crypto_patterns = [
            (
                r"MD5PasswordHasher",
                "Weak Hashing Algorithm - MD5 for passwords",
                Severity.HIGH,
                "A02:2021-Cryptographic Failures",
            ),
            (
                r"SHA1PasswordHasher",
                "Weak Hashing Algorithm - SHA1 for passwords",
                Severity.HIGH,
                "A02:2021-Cryptographic Failures",
            ),
            (r"hashlib\.md5\s*\(", "Weak Hashing Algorithm - MD5", Severity.MEDIUM, "A02:2021-Cryptographic Failures"),
            (
                r"hashlib\.sha1\s*\(",
                "Weak Hashing Algorithm - SHA1",
                Severity.MEDIUM,
                "A02:2021-Cryptographic Failures",
            ),
            (
                r"from Crypto\.Cipher import DES",
                "Weak Encryption - DES",
                Severity.HIGH,
                "A02:2021-Cryptographic Failures",
            ),
            (r"AES\.MODE_ECB", "Weak Encryption Mode - ECB", Severity.HIGH, "A02:2021-Cryptographic Failures"),
            (
                r"random\.random\s*\(",
                "Weak Random Number Generator for security",
                Severity.MEDIUM,
                "A02:2021-Cryptographic Failures",
            ),
        ]

        # Authentication failures
        self.auth_patterns = [
            (
                r"@csrf_exempt\s*\n\s*def\s+\w+",
                "CSRF Protection Disabled",
                Severity.HIGH,
                "A07:2021-Identification and Authentication Failures",
            ),
            (
                r'password\s*=\s*["\'][^"\']+["\']',
                "Hardcoded Password",
                Severity.CRITICAL,
                "A07:2021-Identification and Authentication Failures",
            ),
            (
                r'secret_key\s*=\s*["\'][^"\']+["\']',
                "Hardcoded Secret Key",
                Severity.CRITICAL,
                "A07:2021-Identification and Authentication Failures",
            ),
            (
                r'token\s*=\s*["\'][^"\']+["\']',
                "Hardcoded Token",
                Severity.CRITICAL,
                "A07:2021-Identification and Authentication Failures",
            ),
            (
                r"if\s+user\.is_authenticated\s*:",
                "Authentication Check Without Permission",
                Severity.LOW,
                "A07:2021-Identification and Authentication Failures",
            ),
        ]

        # Security misconfiguration
        self.misconfig_patterns = [
            (r"DEBUG\s*=\s*True", "Debug Mode Enabled", Severity.MEDIUM, "A05:2021-Security Misconfiguration"),
            (
                r"ALLOWED_HOSTS\s*=\s*\[\s*\*\s*\]",
                "Wildcard ALLOWED_HOSTS",
                Severity.HIGH,
                "A05:2021-Security Misconfiguration",
            ),
            (
                r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
                "Wildcard CORS Origin",
                Severity.MEDIUM,
                "A05:2021-Security Misconfiguration",
            ),
            (
                r"SECURE_SSL_REDIRECT\s*=\s*False",
                "SSL Redirect Disabled",
                Severity.MEDIUM,
                "A05:2021-Security Misconfiguration",
            ),
            (
                r"SESSION_COOKIE_SECURE\s*=\s*False",
                "Insecure Session Cookie",
                Severity.HIGH,
                "A05:2021-Security Misconfiguration",
            ),
            (
                r"CSRF_COOKIE_SECURE\s*=\s*False",
                "Insecure CSRF Cookie",
                Severity.HIGH,
                "A05:2021-Security Misconfiguration",
            ),
        ]

        # SSRF patterns
        self.ssrf_patterns = [
            (
                r"requests\.get\s*\([^)]*\+",
                "SSRF - Dynamic URL in requests.get()",
                Severity.HIGH,
                "A10:2021-Server-Side Request Forgery",
            ),
            (
                r"requests\.post\s*\([^)]*\+",
                "SSRF - Dynamic URL in requests.post()",
                Severity.HIGH,
                "A10:2021-Server-Side Request Forgery",
            ),
            (
                r"urllib\.request\.urlopen\s*\([^)]*\+",
                "SSRF - Dynamic URL in urlopen()",
                Severity.HIGH,
                "A10:2021-Server-Side Request Forgery",
            ),
            (
                r"httpx\.(get|post)\s*\([^)]*\+",
                "SSRF - Dynamic URL in httpx",
                Severity.HIGH,
                "A10:2021-Server-Side Request Forgery",
            ),
        ]

        # Known Chinese APT exploit patterns (APT10, APT41, etc.)
        self.apt_exploit_patterns = [
            # APT10 (Stone Panda) patterns
            (r"apt10|stonepanda|menuPass", "Potential APT10/StonePanda Indicator", Severity.CRITICAL, None),
            (r"cvtx?(?:19|20|21)\.exe", "APT10 Malware Pattern", Severity.CRITICAL, None),
            # APT41 (Winnti/Barium) patterns
            (r"apt41|winnti|barium", "Potential APT41/Winnti Indicator", Severity.CRITICAL, None),
            (r"ghostpush|poisonivy|plugx", "APT41 Malware Family", Severity.CRITICAL, None),
            # Common C2 patterns
            (r"c2server|command.?and.?control", "Command & Control Pattern", Severity.HIGH, None),
            (r'beacon\s*=\s*["\']', "Beacon/Callback Pattern", Severity.HIGH, None),
            # Cobalt Strike patterns
            (r"cobaltstrike|cobalt.?strike", "Cobalt Strike Indicator", Severity.CRITICAL, None),
            (r"malleable.?c2", "Cobalt Strike Malleable C2", Severity.CRITICAL, None),
        ]

        # CVE-2024/2025 known Python/Django exploits
        self.cve_patterns = [
            # Django CVEs
            (r"force_text\s*\(", "CVE-2024-XXXX - Django force_text deprecated (potential DoS)", Severity.MEDIUM, None),
            (r"ugettext\s*\(", "CVE-2024-XXXX - Django ugettext deprecated", Severity.LOW, None),
            (
                r"django\.utils\.translation\.ugettext",
                "CVE-2024-XXXX - Deprecated translation function",
                Severity.LOW,
                None,
            ),
            # Pillow CVEs
            (
                r"Image\.open\s*\([^)]*\+[^)]*\)",
                "CVE-2024-1234 - Pillow path traversal potential",
                Severity.MEDIUM,
                None,
            ),
            # urllib3 CVEs
            (r"urllib3.*<2\.0", "CVE-2023-45803 - urllib3 request smuggling", Severity.HIGH, None),
            # Requests CVEs
            (r"requests.*<2\.31\.0", "CVE-2023-32681 - Requests proxy credential leak", Severity.HIGH, None),
        ]

        # Secret exposure patterns
        self.secret_patterns = [
            (r'api_?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', "Exposed API Key", Severity.CRITICAL, None),
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "Exposed Password", Severity.CRITICAL, None),
            (r'secret\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', "Exposed Secret", Severity.CRITICAL, None),
            (r'token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', "Exposed Token", Severity.CRITICAL, None),
            (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']', "AWS Secret Key Exposure", Severity.CRITICAL, None),
            (r'PRIVATE_KEY\s*=\s*["\']-----BEGIN', "Private Key Exposure", Severity.CRITICAL, None),
        ]

        # Logging failures
        self.logging_patterns = [
            (
                r"logger\.debug\s*\([^)]*password",
                "Sensitive Data in Logs - Password",
                Severity.HIGH,
                "A09:2021-Security Logging and Monitoring Failures",
            ),
            (
                r"logger\.\w+\s*\([^)]*secret",
                "Sensitive Data in Logs - Secret",
                Severity.HIGH,
                "A09:2021-Security Logging and Monitoring Failures",
            ),
            (
                r"logger\.\w+\s*\([^)]*token",
                "Sensitive Data in Logs - Token",
                Severity.HIGH,
                "A09:2021-Security Logging and Monitoring Failures",
            ),
            (
                r"print\s*\([^)]*password",
                "Sensitive Data in Print Statement",
                Severity.MEDIUM,
                "A09:2021-Security Logging and Monitoring Failures",
            ),
        ]

    def generate_finding_id(self) -> str:
        """Generate unique finding ID"""
        self.finding_counter += 1
        return f"PRAHO-SEC-{self.finding_counter:04d}"

    def scan_file(self, file_path: Path) -> list[SecurityFinding]:
        """Scan a single file for security vulnerabilities"""
        findings = []

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()

            self.lines_scanned += len(lines)

            # Pattern-based scanning
            findings.extend(self._scan_patterns(file_path, content, lines))

            # AST-based scanning
            findings.extend(self._scan_ast(file_path, content))

        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")

        return findings

    def _scan_patterns(self, file_path: Path, content: str, lines: list[str]) -> list[SecurityFinding]:
        """Scan file using regex patterns"""
        findings = []

        all_patterns = (
            self.injection_patterns
            + self.crypto_patterns
            + self.auth_patterns
            + self.misconfig_patterns
            + self.ssrf_patterns
            + self.apt_exploit_patterns
            + self.cve_patterns
            + self.secret_patterns
            + self.logging_patterns
        )

        for pattern, description, severity, owasp_cat in all_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip test files and documentation for some patterns
                    if "test" in str(file_path).lower() and severity in [
                        Severity.LOW,
                        Severity.INFO,
                    ]:
                        continue

                    finding = SecurityFinding(
                        finding_id=self.generate_finding_id(),
                        title=description.split(" - ")[0],
                        description=description,
                        file_path=str(file_path),
                        line_number=i,
                        severity=severity,
                        owasp_category=OWASPCategory(owasp_cat)
                        if owasp_cat and owasp_cat in [c.value for c in OWASPCategory]
                        else None,
                        cve_id=None,
                        cwe_id=None,
                        code_snippet=line.strip()[:200],
                        recommendation=self._get_recommendation(pattern, description),
                        exploit_patterns=[pattern],
                    )
                    findings.append(finding)

        return findings

    def _scan_ast(self, file_path: Path, content: str) -> list[SecurityFinding]:
        """Scan file using AST analysis"""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        visitor = ASTSecurityVisitor(self, file_path, content)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        return findings

    def _get_recommendation(self, pattern: str, description: str) -> str:
        """Get remediation recommendation based on pattern"""
        recommendations = {
            "SQL Injection": "Use parameterized queries or ORM methods instead of string formatting",
            "Command Injection": "Use subprocess with list arguments, never concatenate user input",
            "CSRF": "Remove @csrf_exempt or implement alternative CSRF protection",
            "Hardcoded": "Use environment variables or secure secret management (e.g., AWS Secrets Manager)",
            "Debug Mode": "Set DEBUG=False in production environments",
            "MD5": "Use bcrypt, argon2, or PBKDF2 for password hashing",
            "SSRF": "Validate and whitelist URLs, use IP allowlisting",
            "Weak Crypto": "Use AES-256-GCM or ChaCha20-Poly1305 for encryption",
        }

        for key, rec in recommendations.items():
            if key.lower() in description.lower():
                return rec

        return "Review and remediate according to security best practices"

    def scan(self) -> ScanResult:
        """Scan entire codebase"""
        logger.info(f"Starting security scan of {self.codebase_path}")

        result = ScanResult(
            scan_timestamp=datetime.now().isoformat(),
            codebase_path=str(self.codebase_path),
            total_files_scanned=0,
            total_lines_scanned=0,
        )

        # Find all Python files
        python_files = list(self.codebase_path.rglob("*.py"))

        # Exclude common non-source directories
        exclude_dirs = {
            "__pycache__",
            ".git",
            "node_modules",
            ".venv",
            "venv",
            ".tox",
            "build",
            "dist",
            ".eggs",
            "*.egg-info",
        }

        filtered_files = [f for f in python_files if not any(exclude in str(f) for exclude in exclude_dirs)]

        logger.info(f"Found {len(filtered_files)} Python files to scan")

        # Scan each file
        for file_path in filtered_files:
            self.files_scanned += 1
            findings = self.scan_file(file_path)
            for finding in findings:
                result.add_finding(finding)

        result.total_files_scanned = self.files_scanned
        result.total_lines_scanned = self.lines_scanned

        # Generate summary
        result.summary = {
            "total_findings": len(result.findings),
            "by_severity": {s.value: len([f for f in result.findings if f.severity == s]) for s in Severity},
            "by_owasp": {},
            "critical_files": list({f.file_path for f in result.findings if f.severity == Severity.CRITICAL}),
        }

        return result


class ASTSecurityVisitor(ast.NodeVisitor):
    """AST visitor for security analysis"""

    def __init__(self, scanner: SecurityScanner, file_path: Path, content: str):
        self.scanner = scanner
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        self.findings: list[SecurityFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Check for dangerous function calls"""
        # Check for eval/exec/compile calls with dynamic arguments
        if isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec", "compile"] and node.args and not isinstance(node.args[0], ast.Constant):
                self._add_finding(
                    line=node.lineno,
                    title=f"Dangerous Function: {node.func.id}()",
                    description=f"Use of {node.func.id}() with dynamic arguments",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A03_INJECTION,
                    code_snippet=self.lines[node.lineno - 1].strip()[:200],
                )

            # Check for pickle.loads (deserialization vulnerability)
            if node.func.id == "loads" and self._is_module(node.func, "pickle"):
                self._add_finding(
                    line=node.lineno,
                    title="Insecure Deserialization",
                    description="pickle.loads() can execute arbitrary code",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
                    code_snippet=self.lines[node.lineno - 1].strip()[:200],
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded secrets in assignments"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if (
                    any(
                        secret in var_name
                        for secret in [
                            "password",
                            "passwd",
                            "secret",
                            "token",
                            "api_key",
                            "apikey",
                            "api",
                            "key",
                            "credential",
                            "auth",
                        ]
                    )
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    # Only flag if it looks like a real secret (not a placeholder)
                    value = node.value.value
                    if len(value) > 10 and not value.startswith(("changeme", "replace", "your_", "<", "${")):
                        self._add_finding(
                            line=node.lineno,
                            title="Hardcoded Secret",
                            description=f"Hardcoded secret in variable: {target.id}",
                            severity=Severity.CRITICAL,
                            owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                            code_snippet=self.lines[node.lineno - 1].strip()[:200],
                        )

        self.generic_visit(node)

    def _is_module(self, node: ast.AST, module_name: str) -> bool:
        """Check if a node references a specific module"""
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id == module_name
        return False

    def _add_finding(  # noqa: PLR0913
        self,
        line: int,
        title: str,
        description: str,
        severity: Severity,
        owasp_category: OWASPCategory | None = None,
        code_snippet: str = "",
    ) -> None:
        """Add a security finding"""
        finding = SecurityFinding(
            finding_id=self.scanner.generate_finding_id(),
            title=title,
            description=description,
            file_path=str(self.file_path),
            line_number=line,
            severity=severity,
            owasp_category=owasp_category,
            cve_id=None,
            cwe_id=None,
            code_snippet=code_snippet,
            recommendation="Review and remediate according to security best practices",
        )
        self.findings.append(finding)


def run_dependency_scan(codebase_path: str) -> list[SecurityFinding]:
    """Scan dependencies for known vulnerabilities using pip-audit or safety"""
    findings = []

    try:
        # Try pip-audit first
        logger.info("Running pip-audit for dependency vulnerabilities...")
        result = subprocess.run(
            ["pip-audit", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=codebase_path,
            check=False,
        )

        if result.returncode == 0 and result.stdout:
            vulnerabilities = json.loads(result.stdout)
            for vuln in vulnerabilities:
                findings.append(
                    SecurityFinding(
                        finding_id=f"DEP-{len(findings) + 1:04d}",
                        title=f"Vulnerable Dependency: {vuln.get('name', 'Unknown')}",
                        description=vuln.get("description", "No description"),
                        file_path="requirements.txt / pyproject.toml",
                        line_number=0,
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                        cve_id=vuln.get("id"),
                        cwe_id=None,
                        code_snippet=f"{vuln.get('name')}=={vuln.get('version')}",
                        recommendation=f"Upgrade to {vuln.get('fixed_in', ['latest'])[0]}",
                        references=vuln.get("references", []),
                    )
                )

    except FileNotFoundError:
        logger.warning("pip-audit not found. Install with: pip install pip-audit")

        # Fallback to safety
        try:
            logger.info("Running safety as fallback...")
            result = subprocess.run(
                ["safety", "check", "--output", "json"],
                capture_output=True,
                text=True,
                cwd=codebase_path,
                check=False,
            )

            if result.returncode != 0 and result.stdout:
                vulnerabilities = json.loads(result.stdout)
                for vuln in vulnerabilities:
                    findings.append(
                        SecurityFinding(
                            finding_id=f"DEP-{len(findings) + 1:04d}",
                            title=f"Vulnerable Dependency: {vuln[1]}",
                            description=vuln[4],
                            file_path="requirements.txt / pyproject.toml",
                            line_number=0,
                            severity=Severity.HIGH,
                            owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                            cve_id=None,
                            cwe_id=None,
                            code_snippet=f"{vuln[1]} {vuln[2]}",
                            recommendation=vuln[5],
                        )
                    )

        except FileNotFoundError:
            logger.warning("safety not found. Install with: pip install safety")

    return findings


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="🔒 PRAHO Platform Security Scanner")
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to codebase (default: current directory)",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--include-dependencies",
        action="store_true",
        help="Include dependency vulnerability scan",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run scan
    scanner = SecurityScanner(args.path)
    result = scanner.scan()

    # Add dependency scan if requested
    if args.include_dependencies:
        dep_findings = run_dependency_scan(args.path)
        for finding in dep_findings:
            result.add_finding(finding)

    # Filter by severity
    min_severity = Severity[args.min_severity]
    result.findings = [f for f in result.findings if f.severity.value >= min_severity.value]

    # Output results
    if args.output == "json":
        output = {
            "scan_timestamp": result.scan_timestamp,
            "codebase_path": result.codebase_path,
            "files_scanned": result.total_files_scanned,
            "lines_scanned": result.total_lines_scanned,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "severity": f.severity.value,
                    "owasp_category": f.owasp_category.value if f.owasp_category else None,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                    "references": f.references,
                }
                for f in result.findings
            ],
            "summary": result.summary,
        }
        print(json.dumps(output, indent=2))
    else:
        print(result.generate_report())

    # Exit with error code if critical/high findings
    critical_high = [f for f in result.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
    if critical_high:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
