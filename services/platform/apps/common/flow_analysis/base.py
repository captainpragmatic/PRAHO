"""
Base types and infrastructure for flow analysis.

Provides foundational classes for both control-flow and data-flow analysis,
enabling systematic detection of logical errors and security vulnerabilities.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AnalysisMode(Enum):
    """Analysis mode for flow analyzer switching."""

    CONTROL_FLOW = "control_flow"
    DATA_FLOW = "data_flow"
    HYBRID = "hybrid"  # Alternates between both modes


class AnalysisSeverity(Enum):
    """Severity level for detected issues."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: AnalysisSeverity) -> bool:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


class IssueCategory(Enum):
    """Categories of detected issues."""

    # Control-flow categories
    INFINITE_LOOP = "infinite_loop"
    UNREACHABLE_CODE = "unreachable_code"
    MISSING_BRANCH = "missing_branch"
    DEAD_CODE = "dead_code"
    EXCEPTION_FLOW = "exception_flow"
    LOOP_INVARIANT = "loop_invariant"
    CONDITIONAL_LOGIC = "conditional_logic"

    # Data-flow categories
    SQL_INJECTION = "sql_injection"
    XSS_VULNERABILITY = "xss_vulnerability"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    TAINTED_DATA = "tainted_data"
    UNVALIDATED_INPUT = "unvalidated_input"
    SENSITIVE_DATA_LEAK = "sensitive_data_leak"
    BUFFER_OVERFLOW = "buffer_overflow"  # Python context: large allocations
    INSECURE_DESERIALIZATION = "insecure_deserialization"

    # Branch coverage categories
    UNCOVERED_BRANCH = "uncovered_branch"
    MISSING_ELSE = "missing_else"
    MISSING_EXCEPTION_HANDLER = "missing_exception_handler"


@dataclass(frozen=True)
class CodeLocation:
    """Precise location in source code."""

    file_path: str
    line_number: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None

    def __str__(self) -> str:
        location = f"{self.file_path}:{self.line_number}"
        if self.column:
            location += f":{self.column}"
        return location

    @classmethod
    def from_ast_node(cls, node: ast.AST, file_path: str) -> CodeLocation:
        """Create location from AST node."""
        return cls(
            file_path=file_path,
            line_number=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
        )


@dataclass
class FlowIssue:
    """A detected issue from flow analysis."""

    category: IssueCategory
    severity: AnalysisSeverity
    message: str
    location: CodeLocation
    mode: AnalysisMode
    code_snippet: str = ""
    remediation: str = ""
    cwe_id: str | None = None  # Common Weakness Enumeration ID
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.category.value}: {self.message} at {self.location}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "location": str(self.location),
            "file": self.location.file_path,
            "line": self.location.line_number,
            "column": self.location.column,
            "mode": self.mode.value,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    """Complete result from flow analysis."""

    issues: list[FlowIssue] = field(default_factory=list)
    files_analyzed: int = 0
    total_lines: int = 0
    analysis_mode: AnalysisMode = AnalysisMode.HYBRID
    branches_covered: int = 0
    branches_total: int = 0
    taint_sources_found: int = 0
    control_flow_nodes: int = 0
    execution_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def branch_coverage_percent(self) -> float:
        """Calculate branch coverage percentage."""
        if self.branches_total == 0:
            return 100.0
        return (self.branches_covered / self.branches_total) * 100

    @property
    def issue_count_by_severity(self) -> dict[str, int]:
        """Count issues by severity level."""
        counts: dict[str, int] = {}
        for issue in self.issues:
            severity = issue.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    @property
    def has_critical_issues(self) -> bool:
        """Check if any critical issues were found."""
        return any(i.severity == AnalysisSeverity.CRITICAL for i in self.issues)

    @property
    def has_security_issues(self) -> bool:
        """Check if any security-related issues were found."""
        security_categories = {
            IssueCategory.SQL_INJECTION,
            IssueCategory.XSS_VULNERABILITY,
            IssueCategory.COMMAND_INJECTION,
            IssueCategory.PATH_TRAVERSAL,
            IssueCategory.INSECURE_DESERIALIZATION,
            IssueCategory.SENSITIVE_DATA_LEAK,
        }
        return any(i.category in security_categories for i in self.issues)

    def merge(self, other: AnalysisResult) -> AnalysisResult:
        """Merge two analysis results."""
        return AnalysisResult(
            issues=self.issues + other.issues,
            files_analyzed=self.files_analyzed + other.files_analyzed,
            total_lines=self.total_lines + other.total_lines,
            analysis_mode=self.analysis_mode,
            branches_covered=self.branches_covered + other.branches_covered,
            branches_total=self.branches_total + other.branches_total,
            taint_sources_found=self.taint_sources_found + other.taint_sources_found,
            control_flow_nodes=self.control_flow_nodes + other.control_flow_nodes,
            execution_time_ms=self.execution_time_ms + other.execution_time_ms,
            errors=self.errors + other.errors,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "issues": [i.to_dict() for i in self.issues],
            "summary": {
                "files_analyzed": self.files_analyzed,
                "total_lines": self.total_lines,
                "analysis_mode": self.analysis_mode.value,
                "branches_covered": self.branches_covered,
                "branches_total": self.branches_total,
                "branch_coverage_percent": round(self.branch_coverage_percent, 2),
                "taint_sources_found": self.taint_sources_found,
                "control_flow_nodes": self.control_flow_nodes,
                "execution_time_ms": round(self.execution_time_ms, 2),
                "issue_counts": self.issue_count_by_severity,
                "has_critical_issues": self.has_critical_issues,
                "has_security_issues": self.has_security_issues,
            },
            "errors": self.errors,
        }


@dataclass
class AnalysisContext:
    """Context for flow analysis operations."""

    file_path: str
    source_code: str
    ast_tree: ast.Module | None = None
    current_function: str | None = None
    current_class: str | None = None
    scope_stack: list[str] = field(default_factory=list)
    taint_sources: set[str] = field(default_factory=set)
    sanitized_vars: set[str] = field(default_factory=set)
    defined_vars: set[str] = field(default_factory=set)
    used_vars: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        """Parse AST if not provided."""
        if self.ast_tree is None and self.source_code:
            try:
                self.ast_tree = ast.parse(self.source_code)
            except SyntaxError as e:
                logger.warning(f"Failed to parse {self.file_path}: {e}")

    @classmethod
    def from_file(cls, file_path: str | Path) -> AnalysisContext:
        """Create context from file path."""
        path = Path(file_path)
        try:
            source_code = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            source_code = ""
        return cls(file_path=str(path), source_code=source_code)

    def enter_scope(self, name: str) -> None:
        """Enter a new scope (class or function)."""
        self.scope_stack.append(name)

    def exit_scope(self) -> str | None:
        """Exit current scope."""
        if self.scope_stack:
            return self.scope_stack.pop()
        return None

    @property
    def current_scope(self) -> str:
        """Get current scope name."""
        if self.scope_stack:
            return ".".join(self.scope_stack)
        return "<module>"

    def mark_tainted(self, var_name: str) -> None:
        """Mark a variable as tainted (user input)."""
        self.taint_sources.add(var_name)
        # Remove from sanitized if it was there
        self.sanitized_vars.discard(var_name)

    def mark_sanitized(self, var_name: str) -> None:
        """Mark a variable as sanitized."""
        self.sanitized_vars.add(var_name)
        # Remove from tainted
        self.taint_sources.discard(var_name)

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted."""
        return var_name in self.taint_sources and var_name not in self.sanitized_vars


class BaseFlowAnalyzer:
    """Base class for flow analyzers."""

    def __init__(self) -> None:
        self.issues: list[FlowIssue] = []
        self.mode = AnalysisMode.CONTROL_FLOW

    def analyze(self, context: AnalysisContext) -> list[FlowIssue]:
        """Analyze code and return issues. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement analyze()")

    def add_issue(  # noqa: PLR0913
        self,
        category: IssueCategory,
        severity: AnalysisSeverity,
        message: str,
        location: CodeLocation,
        code_snippet: str = "",
        remediation: str = "",
        cwe_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a detected issue."""
        issue = FlowIssue(
            category=category,
            severity=severity,
            message=message,
            location=location,
            mode=self.mode,
            code_snippet=code_snippet,
            remediation=remediation,
            cwe_id=cwe_id,
            metadata=metadata or {},
        )
        self.issues.append(issue)
        logger.debug(f"Detected issue: {issue}")

    def reset(self) -> None:
        """Reset analyzer state."""
        self.issues = []

    def get_source_line(self, context: AnalysisContext, line_number: int) -> str:
        """Get source code line by number."""
        lines = context.source_code.splitlines()
        if 0 < line_number <= len(lines):
            return lines[line_number - 1].strip()
        return ""
