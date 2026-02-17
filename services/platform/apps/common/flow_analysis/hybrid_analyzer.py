"""
Hybrid Flow Analyzer - PRAHO Platform

Alternates between control-flow and data-flow analysis for comprehensive
code examination. This approach provides:

1. Control-flow analysis: Finds logical errors in loops, conditionals
2. Data-flow analysis: Identifies security vulnerabilities like injection attacks
3. Combined insights: Cross-references findings from both analyses

The hybrid approach is more effective than running analyses independently,
as it can correlate control-flow paths with data-flow taint propagation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apps.common.flow_analysis.base import (
    AnalysisContext,
    AnalysisMode,
    AnalysisResult,
    AnalysisSeverity,
    FlowIssue,
    IssueCategory,
)
from apps.common.flow_analysis.branch_coverage import BranchCoverageAnalyzer
from apps.common.flow_analysis.control_flow import ControlFlowAnalyzer
from apps.common.flow_analysis.data_flow import DataFlowAnalyzer

logger = logging.getLogger(__name__)

PROXIMITY_LINE_THRESHOLD = 5


@dataclass
class AnalysisPass:
    """Represents one pass of analysis."""

    mode: AnalysisMode
    pass_number: int
    issues_found: int = 0
    execution_time_ms: float = 0.0


@dataclass
class HybridAnalysisConfig:
    """Configuration for hybrid flow analysis."""

    # Analysis modes to run
    enable_control_flow: bool = True
    enable_data_flow: bool = True
    enable_branch_coverage: bool = True

    # Analysis behavior
    max_passes: int = 3  # Maximum analysis passes per mode
    cross_reference_results: bool = True  # Correlate findings between modes
    stop_on_critical: bool = False  # Stop analysis if critical issue found

    # File filtering
    include_patterns: list[str] = field(default_factory=lambda: ["*.py"])
    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "**/migrations/*",
            "**/tests/*",
            "**/__pycache__/*",
            "**/venv/*",
            "**/.venv/*",
        ]
    )

    # Severity filtering
    min_severity: AnalysisSeverity = AnalysisSeverity.LOW


class HybridFlowAnalyzer:
    """
    Alternates between control-flow and data-flow analysis.

    This analyzer provides comprehensive code examination by:
    1. Running control-flow analysis to identify logical issues
    2. Switching to data-flow analysis for security vulnerabilities
    3. Cross-referencing findings to provide deeper insights
    4. Checking branch coverage for complete path analysis

    Usage:
        analyzer = HybridFlowAnalyzer()
        result = analyzer.analyze_file("path/to/file.py")
        # or
        result = analyzer.analyze_directory("path/to/project")
    """

    def __init__(self, config: HybridAnalysisConfig | None = None) -> None:
        self.config = config or HybridAnalysisConfig()
        self.control_flow_analyzer = ControlFlowAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.branch_coverage_analyzer = BranchCoverageAnalyzer()
        self.passes: list[AnalysisPass] = []
        self.current_mode = AnalysisMode.CONTROL_FLOW

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """
        Analyze a single file with hybrid mode switching.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            AnalysisResult with all detected issues
        """
        start_time = time.time()
        path = Path(file_path)

        if not path.exists():
            return AnalysisResult(
                errors=[f"File not found: {file_path}"],
                analysis_mode=AnalysisMode.HYBRID,
            )

        if path.suffix != ".py":
            return AnalysisResult(
                errors=[f"Not a Python file: {file_path}"],
                analysis_mode=AnalysisMode.HYBRID,
            )

        # Create analysis context
        context = AnalysisContext.from_file(path)
        if context.ast_tree is None:
            return AnalysisResult(
                errors=[f"Failed to parse: {file_path}"],
                files_analyzed=1,
                analysis_mode=AnalysisMode.HYBRID,
            )

        # Run hybrid analysis
        all_issues: list[FlowIssue] = []
        self.passes = []

        # Pass 1: Control-flow analysis
        if self.config.enable_control_flow:
            control_issues = self._run_control_flow_pass(context)
            all_issues.extend(control_issues)

            if self.config.stop_on_critical and self._has_critical(control_issues):
                return self._build_result(all_issues, context, start_time)

        # Pass 2: Data-flow analysis
        if self.config.enable_data_flow:
            data_issues = self._run_data_flow_pass(context)
            all_issues.extend(data_issues)

            if self.config.stop_on_critical and self._has_critical(data_issues):
                return self._build_result(all_issues, context, start_time)

        # Pass 3: Branch coverage analysis
        if self.config.enable_branch_coverage:
            branch_issues = self._run_branch_coverage_pass(context)
            all_issues.extend(branch_issues)

        # Cross-reference findings
        if self.config.cross_reference_results:
            cross_ref_issues = self._cross_reference_findings(all_issues, context)
            all_issues.extend(cross_ref_issues)

        # Filter by minimum severity
        all_issues = [i for i in all_issues if i.severity >= self.config.min_severity]

        return self._build_result(all_issues, context, start_time)

    def analyze_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> AnalysisResult:
        """
        Analyze all Python files in a directory.

        Args:
            directory: Path to directory to analyze
            recursive: Whether to recurse into subdirectories

        Returns:
            Combined AnalysisResult from all files
        """
        start_time = time.time()
        dir_path = Path(directory)

        if not dir_path.exists():
            return AnalysisResult(
                errors=[f"Directory not found: {directory}"],
                analysis_mode=AnalysisMode.HYBRID,
            )

        # Find Python files
        pattern = "**/*.py" if recursive else "*.py"
        files = list(dir_path.glob(pattern))

        # Apply exclude patterns
        files = [f for f in files if not any(f.match(exc) for exc in self.config.exclude_patterns)]

        if not files:
            return AnalysisResult(
                errors=[f"No Python files found in: {directory}"],
                analysis_mode=AnalysisMode.HYBRID,
            )

        # Analyze each file
        combined_result = AnalysisResult(analysis_mode=AnalysisMode.HYBRID)

        for file_path in files:
            try:
                file_result = self.analyze_file(file_path)
                combined_result = combined_result.merge(file_result)

                if self.config.stop_on_critical and file_result.has_critical_issues:
                    break
            except Exception as e:
                combined_result.errors.append(f"Error analyzing {file_path}: {e}")
                logger.warning(f"Failed to analyze {file_path}: {e}")

        combined_result.execution_time_ms = (time.time() - start_time) * 1000
        return combined_result

    def _run_control_flow_pass(self, context: AnalysisContext) -> list[FlowIssue]:
        """Run control-flow analysis pass."""
        pass_start = time.time()
        self.current_mode = AnalysisMode.CONTROL_FLOW

        self.control_flow_analyzer.reset()
        issues = self.control_flow_analyzer.analyze(context)

        self.passes.append(
            AnalysisPass(
                mode=AnalysisMode.CONTROL_FLOW,
                pass_number=len(self.passes) + 1,
                issues_found=len(issues),
                execution_time_ms=(time.time() - pass_start) * 1000,
            )
        )

        logger.debug(f"Control-flow pass found {len(issues)} issues")
        return issues

    def _run_data_flow_pass(self, context: AnalysisContext) -> list[FlowIssue]:
        """Run data-flow analysis pass."""
        pass_start = time.time()
        self.current_mode = AnalysisMode.DATA_FLOW

        self.data_flow_analyzer.reset()
        issues = self.data_flow_analyzer.analyze(context)

        self.passes.append(
            AnalysisPass(
                mode=AnalysisMode.DATA_FLOW,
                pass_number=len(self.passes) + 1,
                issues_found=len(issues),
                execution_time_ms=(time.time() - pass_start) * 1000,
            )
        )

        logger.debug(f"Data-flow pass found {len(issues)} issues")
        return issues

    def _run_branch_coverage_pass(self, context: AnalysisContext) -> list[FlowIssue]:
        """Run branch coverage analysis pass."""
        pass_start = time.time()

        self.branch_coverage_analyzer.reset()
        issues = self.branch_coverage_analyzer.analyze(context)

        self.passes.append(
            AnalysisPass(
                mode=AnalysisMode.CONTROL_FLOW,  # Branch coverage is control-flow related
                pass_number=len(self.passes) + 1,
                issues_found=len(issues),
                execution_time_ms=(time.time() - pass_start) * 1000,
            )
        )

        logger.debug(f"Branch coverage pass found {len(issues)} issues")
        return issues

    def _cross_reference_findings(
        self,
        issues: list[FlowIssue],
        context: AnalysisContext,
    ) -> list[FlowIssue]:
        """
        Cross-reference findings between control-flow and data-flow analyses.

        This can identify:
        - Security issues in unreachable code (low priority)
        - Tainted data in infinite loops (amplified severity)
        - Missing sanitization in exception handlers
        """
        cross_ref_issues: list[FlowIssue] = []

        # Get issues by category for cross-referencing
        control_issues = [i for i in issues if i.mode == AnalysisMode.CONTROL_FLOW]
        data_issues = [i for i in issues if i.mode == AnalysisMode.DATA_FLOW]

        # Check for tainted data in potentially infinite loops
        infinite_loop_lines = {
            i.location.line_number for i in control_issues if i.category == IssueCategory.INFINITE_LOOP
        }

        cross_ref_issues.extend(
            FlowIssue(
                category=IssueCategory.TAINTED_DATA,
                severity=AnalysisSeverity.CRITICAL,
                message=(f"AMPLIFIED: {data_issue.message} - occurs in potential infinite loop"),
                location=data_issue.location,
                mode=AnalysisMode.HYBRID,
                code_snippet=data_issue.code_snippet,
                remediation=(f"{data_issue.remediation} Additionally, fix the infinite loop."),
                cwe_id=data_issue.cwe_id,
                metadata={
                    **data_issue.metadata,
                    "cross_reference": "infinite_loop",
                },
            )
            for data_issue in data_issues
            if data_issue.location.line_number in infinite_loop_lines
        )

        # Check for security issues in unreachable code
        unreachable_lines = {
            i.location.line_number for i in control_issues if i.category == IssueCategory.UNREACHABLE_CODE
        }

        cross_ref_issues.extend(
            FlowIssue(
                category=data_issue.category,
                severity=AnalysisSeverity.LOW,  # Lower because unreachable
                message=f"UNREACHABLE: {data_issue.message} - in dead code",
                location=data_issue.location,
                mode=AnalysisMode.HYBRID,
                code_snippet=data_issue.code_snippet,
                remediation="Remove the dead code or fix the control flow to make it reachable.",
                cwe_id=data_issue.cwe_id,
                metadata={
                    **data_issue.metadata,
                    "cross_reference": "unreachable_code",
                },
            )
            for data_issue in data_issues
            if data_issue.location.line_number in unreachable_lines
        )

        # Check for missing exception handlers with tainted data
        exception_issues = [i for i in control_issues if i.category == IssueCategory.EXCEPTION_FLOW]

        for exc_issue in exception_issues:
            # Look for nearby tainted data usage
            for data_issue in data_issues:
                line_diff = abs(data_issue.location.line_number - exc_issue.location.line_number)
                if line_diff <= PROXIMITY_LINE_THRESHOLD:  # Within 5 lines
                    cross_ref_issues.append(
                        FlowIssue(
                            category=IssueCategory.TAINTED_DATA,
                            severity=AnalysisSeverity.HIGH,
                            message=(f"EXCEPTION CONTEXT: {data_issue.message} - " f"near improper exception handling"),
                            location=data_issue.location,
                            mode=AnalysisMode.HYBRID,
                            code_snippet=data_issue.code_snippet,
                            remediation=(f"{data_issue.remediation} " f"Also ensure proper exception handling."),
                            cwe_id=data_issue.cwe_id,
                            metadata={
                                **data_issue.metadata,
                                "cross_reference": "exception_handling",
                            },
                        )
                    )

        return cross_ref_issues

    def _build_result(
        self,
        issues: list[FlowIssue],
        context: AnalysisContext,
        start_time: float,
    ) -> AnalysisResult:
        """Build the final analysis result."""
        # Count lines
        total_lines = len(context.source_code.splitlines()) if context.source_code else 0

        # Get branch coverage info
        branches_covered = self.branch_coverage_analyzer.branches_covered
        branches_total = self.branch_coverage_analyzer.branches_total

        # Get control-flow node count
        control_flow_nodes = len(self.control_flow_analyzer.cfg.nodes)

        # Get taint sources count
        taint_sources = len(self.data_flow_analyzer.tainted_vars)

        return AnalysisResult(
            issues=issues,
            files_analyzed=1,
            total_lines=total_lines,
            analysis_mode=AnalysisMode.HYBRID,
            branches_covered=branches_covered,
            branches_total=branches_total,
            taint_sources_found=taint_sources,
            control_flow_nodes=control_flow_nodes,
            execution_time_ms=(time.time() - start_time) * 1000,
        )

    def _has_critical(self, issues: list[FlowIssue]) -> bool:
        """Check if any issues are critical severity."""
        return any(i.severity == AnalysisSeverity.CRITICAL for i in issues)

    def get_analysis_summary(self) -> dict[str, Any]:
        """Get a summary of the analysis passes performed."""
        return {
            "passes": [
                {
                    "mode": p.mode.value,
                    "pass_number": p.pass_number,
                    "issues_found": p.issues_found,
                    "execution_time_ms": round(p.execution_time_ms, 2),
                }
                for p in self.passes
            ],
            "total_passes": len(self.passes),
            "modes_used": list({p.mode.value for p in self.passes}),
        }


def analyze_code(  # noqa: PLR0911
    source: str | Path,
    config: HybridAnalysisConfig | None = None,
) -> AnalysisResult:
    """
    Convenience function to analyze code with hybrid mode.

    Args:
        source: Either a file path, directory path, or source code string
        config: Optional configuration for the analyzer

    Returns:
        AnalysisResult with all detected issues
    """
    analyzer = HybridFlowAnalyzer(config)

    if isinstance(source, Path):
        if source.is_dir():
            return analyzer.analyze_directory(source)
        else:
            return analyzer.analyze_file(source)
    elif isinstance(source, str):
        # Check if it's a path (skip empty/multiline strings — newlines mean source code, not a path)
        path = Path(source) if source.strip() and "\n" not in source else None
        if path is not None and path.exists():
            if path.is_dir():
                return analyzer.analyze_directory(path)
            else:
                return analyzer.analyze_file(path)
        else:
            # Treat as source code
            context = AnalysisContext(
                file_path="<string>",
                source_code=source,
            )
            if context.ast_tree is None:
                return AnalysisResult(
                    errors=["Failed to parse source code"],
                    analysis_mode=AnalysisMode.HYBRID,
                )

            # Run hybrid analysis
            all_issues: list[FlowIssue] = []
            if config is None or config.enable_control_flow:
                analyzer.control_flow_analyzer.reset()
                all_issues.extend(analyzer.control_flow_analyzer.analyze(context))

            if config is None or config.enable_data_flow:
                analyzer.data_flow_analyzer.reset()
                all_issues.extend(analyzer.data_flow_analyzer.analyze(context))

            if config is None or config.enable_branch_coverage:
                analyzer.branch_coverage_analyzer.reset()
                all_issues.extend(analyzer.branch_coverage_analyzer.analyze(context))

            return AnalysisResult(
                issues=all_issues,
                files_analyzed=1,
                total_lines=len(source.splitlines()),
                analysis_mode=AnalysisMode.HYBRID,
            )

    return AnalysisResult(
        errors=["Invalid source provided"],
        analysis_mode=AnalysisMode.HYBRID,
    )
