"""
Branch Coverage Analyzer - PRAHO Platform

Analyzes code for complete branch coverage, ensuring all possible
execution paths are considered. This is crucial for:

1. Finding missing else branches
2. Identifying uncovered exception handlers
3. Detecting incomplete switch/match patterns
4. Ensuring all loop paths are considered

Branch coverage analysis complements control-flow analysis by
focusing specifically on decision points and their outcomes.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Any

from apps.common.flow_analysis.base import (
    AnalysisContext,
    AnalysisMode,
    AnalysisSeverity,
    BaseFlowAnalyzer,
    CodeLocation,
    FlowIssue,
    IssueCategory,
)

logger = logging.getLogger(__name__)


@dataclass
class Branch:
    """Represents a branch in the code."""

    id: int
    branch_type: str  # "if", "elif", "else", "except", "for-else", "while-else", "match-case"
    location: CodeLocation
    condition: str | None = None
    has_body: bool = True
    parent_branch_id: int | None = None


@dataclass
class BranchPoint:
    """A decision point with multiple branches."""

    id: int
    point_type: str  # "if-chain", "try-except", "loop", "match"
    location: CodeLocation
    branches: list[Branch] = field(default_factory=list)
    has_default: bool = False  # Has else/default/bare except
    total_branches: int = 0
    covered_branches: int = 0

    @property
    def is_complete(self) -> bool:
        """Check if all branches are covered."""
        return self.has_default or len(self.branches) == self.total_branches


class BranchCoverageAnalyzer(BaseFlowAnalyzer, ast.NodeVisitor):
    """
    Analyzes branch coverage to ensure all execution paths are considered.

    Detects:
    - Missing else branches in if statements
    - Missing exception handlers for specific exceptions
    - Incomplete match/case patterns
    - Missing for/while else clauses where relevant
    - Uncovered conditional expressions
    """

    def __init__(self) -> None:
        super().__init__()
        self.mode = AnalysisMode.CONTROL_FLOW
        self.context: AnalysisContext | None = None
        self.branch_points: list[BranchPoint] = []
        self.branches: list[Branch] = []
        self.branch_id_counter = 0
        self.branch_point_id_counter = 0
        self.current_function: str | None = None
        self.branches_total = 0
        self.branches_covered = 0

    def analyze(self, context: AnalysisContext) -> list[FlowIssue]:
        """Analyze branch coverage and return detected issues."""
        self.reset()
        self.context = context

        if context.ast_tree is None:
            return []

        try:
            self.visit(context.ast_tree)
            self._analyze_branch_coverage()
        except Exception as e:
            logger.warning(f"Branch coverage analysis error in {context.file_path}: {e}")

        return self.issues

    def reset(self) -> None:
        """Reset analyzer state."""
        super().reset()
        self.branch_points = []
        self.branches = []
        self.branch_id_counter = 0
        self.branch_point_id_counter = 0
        self.current_function = None
        self.branches_total = 0
        self.branches_covered = 0

    def _create_branch(
        self,
        branch_type: str,
        node: ast.AST,
        condition: str | None = None,
        has_body: bool = True,
        parent_id: int | None = None,
    ) -> Branch:
        """Create a new branch."""
        if self.context is None:
            file_path = "<unknown>"
        else:
            file_path = self.context.file_path

        branch = Branch(
            id=self.branch_id_counter,
            branch_type=branch_type,
            location=CodeLocation.from_ast_node(node, file_path),
            condition=condition,
            has_body=has_body,
            parent_branch_id=parent_id,
        )
        self.branch_id_counter += 1
        self.branches.append(branch)
        return branch

    def _create_branch_point(
        self,
        point_type: str,
        node: ast.AST,
    ) -> BranchPoint:
        """Create a new branch point."""
        if self.context is None:
            file_path = "<unknown>"
        else:
            file_path = self.context.file_path

        point = BranchPoint(
            id=self.branch_point_id_counter,
            point_type=point_type,
            location=CodeLocation.from_ast_node(node, file_path),
        )
        self.branch_point_id_counter += 1
        self.branch_points.append(point)
        return point

    def _analyze_branch_coverage(self) -> None:
        """Analyze all branch points for coverage issues."""
        for point in self.branch_points:
            self.branches_total += len(point.branches) + (1 if not point.has_default else 0)
            self.branches_covered += len(point.branches)

            if not point.is_complete:
                self._report_incomplete_branch_point(point)

    def _report_incomplete_branch_point(self, point: BranchPoint) -> None:
        """Report an incomplete branch point."""
        if self.context is None:
            return

        message = self._get_incomplete_message(point)
        remediation = self._get_remediation(point)
        severity = self._get_severity(point)

        self.add_issue(
            category=IssueCategory.MISSING_BRANCH,
            severity=severity,
            message=message,
            location=point.location,
            code_snippet=self.get_source_line(self.context, point.location.line_number),
            remediation=remediation,
            metadata={
                "branch_point_type": point.point_type,
                "branches_found": len(point.branches),
                "has_default": point.has_default,
            },
        )

    def _get_incomplete_message(self, point: BranchPoint) -> str:
        """Get message for incomplete branch point."""
        if point.point_type == "if-chain":
            return "If statement without else branch - not all cases handled"
        elif point.point_type == "try-except":
            return "Try block without broad exception handler - may miss exceptions"
        elif point.point_type == "match":
            return "Match statement without default case - not all patterns covered"
        elif point.point_type == "loop":
            return "Loop without else clause - break path not explicitly handled"
        else:
            return f"Incomplete branch coverage in {point.point_type}"

    def _get_remediation(self, point: BranchPoint) -> str:
        """Get remediation advice for incomplete branch point."""
        if point.point_type == "if-chain":
            return (
                "Add an 'else' branch to handle all cases explicitly, " "or document why the else case is impossible."
            )
        elif point.point_type == "try-except":
            return (
                "Consider adding a broader exception handler for unexpected errors, "
                "or use 'except Exception' as a fallback."
            )
        elif point.point_type == "match":
            return (
                "Add a 'case _:' default pattern to handle unmatched cases, "
                "or ensure all possible values are covered."
            )
        elif point.point_type == "loop":
            return (
                "Consider adding an 'else' clause to the loop if the break path "
                "should be explicitly distinguished from normal completion."
            )
        else:
            return "Ensure all branches are handled explicitly."

    def _get_severity(self, point: BranchPoint) -> AnalysisSeverity:
        """Get severity based on branch point type."""
        severity_map = {
            "try-except": AnalysisSeverity.MEDIUM,
            "match": AnalysisSeverity.MEDIUM,
            "if-chain": AnalysisSeverity.LOW,
            "loop": AnalysisSeverity.INFO,
        }
        return severity_map.get(point.point_type, AnalysisSeverity.LOW)

    # AST Visitor Methods

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track current function for context."""
        old_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)

        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function."""
        old_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)

        self.current_function = old_function

    def visit_If(self, node: ast.If) -> None:
        """Analyze if statement for branch coverage."""
        self._analyze_if_chain(node)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Analyze try-except for exception coverage."""
        self._analyze_try_except(node)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        """Analyze match statement for pattern coverage."""
        self._analyze_match(node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Analyze for loop for else clause."""
        self._analyze_loop(node, "for")
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        """Analyze while loop for else clause."""
        self._analyze_loop(node, "while")
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        """Analyze conditional expression (ternary operator)."""
        # Ternary always has both branches, so fully covered
        if self.context:
            point = self._create_branch_point("ternary", node)

            # True branch
            self._create_branch(
                "true",
                node.body,
                condition=self._get_condition_str(node.test),
            )
            point.branches.append(self.branches[-1])

            # False branch
            self._create_branch(
                "false",
                node.orelse,
            )
            point.branches.append(self.branches[-1])

            point.has_default = True  # Ternary always has both branches
            point.total_branches = 2

        self.generic_visit(node)

    def _analyze_if_chain(self, node: ast.If) -> None:
        """Analyze if-elif-else chain for completeness."""
        if self.context is None:
            return

        point = self._create_branch_point("if-chain", node)

        # Main if branch
        if_branch = self._create_branch(
            "if",
            node,
            condition=self._get_condition_str(node.test),
        )
        point.branches.append(if_branch)
        point.total_branches = 1

        # Count elif branches
        current: ast.If | None = node
        while current and current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                # This is an elif
                elif_node = current.orelse[0]
                elif_branch = self._create_branch(
                    "elif",
                    elif_node,
                    condition=self._get_condition_str(elif_node.test),
                    parent_id=if_branch.id,
                )
                point.branches.append(elif_branch)
                point.total_branches += 1
                current = elif_node
            else:
                # This is an else
                else_branch = self._create_branch(
                    "else",
                    current.orelse[0] if current.orelse else current,
                    parent_id=if_branch.id,
                )
                point.branches.append(else_branch)
                point.has_default = True
                point.total_branches += 1
                break

        # Check if we need an else
        if not point.has_default:
            # Check if this is in a function that always returns in all branches
            if self._should_require_else(node):
                point.total_branches += 1  # Account for missing else

    def _analyze_try_except(self, node: ast.Try) -> None:
        """Analyze try-except for exception coverage."""
        if self.context is None:
            return

        point = self._create_branch_point("try-except", node)

        # Check each exception handler
        has_base_exception = False
        has_bare_except = False

        for handler in node.handlers:
            if handler.type is None:
                # Bare except - catches everything
                has_bare_except = True
                branch = self._create_branch(
                    "except",
                    handler,
                    condition="bare except",
                )
            elif isinstance(handler.type, ast.Name):
                exc_name = handler.type.id
                if exc_name in ("Exception", "BaseException"):
                    has_base_exception = True
                branch = self._create_branch(
                    "except",
                    handler,
                    condition=exc_name,
                )
            elif isinstance(handler.type, ast.Tuple):
                # Multiple exception types
                exc_names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
                if "Exception" in exc_names or "BaseException" in exc_names:
                    has_base_exception = True
                branch = self._create_branch(
                    "except",
                    handler,
                    condition=", ".join(exc_names),
                )
            else:
                branch = self._create_branch(
                    "except",
                    handler,
                    condition="unknown",
                )

            point.branches.append(branch)

        point.total_branches = len(node.handlers)
        point.has_default = has_bare_except or has_base_exception

        # Check for finally
        if node.finalbody:
            finally_branch = self._create_branch(
                "finally",
                node.finalbody[0],
            )
            point.branches.append(finally_branch)

    def _analyze_match(self, node: ast.Match) -> None:
        """Analyze match statement for pattern coverage."""
        if self.context is None:
            return

        point = self._create_branch_point("match", node)

        has_wildcard = False

        for case in node.cases:
            # Check for wildcard pattern
            if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                has_wildcard = True

            pattern_str = self._get_pattern_str(case.pattern)
            branch = self._create_branch(
                "case",
                case,
                condition=pattern_str,
            )
            point.branches.append(branch)

        point.total_branches = len(node.cases)
        point.has_default = has_wildcard

        if not has_wildcard:
            point.total_branches += 1  # Account for missing default

    def _analyze_loop(self, node: ast.For | ast.While, loop_type: str) -> None:
        """Analyze loop for else clause."""
        if self.context is None:
            return

        # Check if loop has break statement
        has_break = any(
            isinstance(child, ast.Break)
            for child in ast.walk(node)
            if child is not node  # Don't count nested loops
        )

        if has_break:
            # If there's a break, else clause becomes more relevant
            point = self._create_branch_point("loop", node)

            # Normal completion branch
            normal_branch = self._create_branch(
                f"{loop_type}-complete",
                node,
                condition="loop completes normally",
            )
            point.branches.append(normal_branch)

            # Break branch
            break_branch = self._create_branch(
                f"{loop_type}-break",
                node,
                condition="break executed",
            )
            point.branches.append(break_branch)

            point.total_branches = 2
            point.has_default = bool(node.orelse)  # else clause handles break

            if node.orelse:
                else_branch = self._create_branch(
                    f"{loop_type}-else",
                    node.orelse[0],
                )
                point.branches.append(else_branch)

    def _should_require_else(self, node: ast.If) -> bool:
        """Determine if an if statement should require an else branch."""
        if self.context is None:
            return False

        # If all if/elif branches return/raise, else might be expected
        all_branches_terminate = self._all_branches_terminate(node)

        # If we're in a function that should return a value
        # and all branches terminate, we might need else

        return all_branches_terminate and self.current_function is not None

    def _all_branches_terminate(self, node: ast.If) -> bool:
        """Check if all branches in an if chain terminate (return/raise)."""

        def terminates(stmts: list[ast.stmt]) -> bool:
            for stmt in stmts:
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    return True
            return False

        if not terminates(node.body):
            return False

        current: ast.If | None = node
        while current and current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                if not terminates(current.orelse[0].body):
                    return False
                current = current.orelse[0]
            else:
                # Has else - check if it terminates
                return terminates(current.orelse)

        return True

    def _get_condition_str(self, node: ast.expr) -> str:
        """Get a string representation of a condition."""
        if isinstance(node, ast.Compare):
            return self._format_compare(node)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return f"not {self._get_condition_str(node.operand)}"
        elif isinstance(node, ast.BoolOp):
            op_str = " and " if isinstance(node.op, ast.And) else " or "
            return op_str.join(self._get_condition_str(v) for v in node.values)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}(...)"
            elif isinstance(node.func, ast.Attribute):
                return f"...{node.func.attr}(...)"
        return "..."

    def _format_compare(self, node: ast.Compare) -> str:
        """Format a comparison expression."""
        if isinstance(node.left, ast.Name):
            left = node.left.id
        else:
            left = "..."

        if len(node.ops) == 1 and len(node.comparators) == 1:
            op = self._format_cmpop(node.ops[0])
            if isinstance(node.comparators[0], ast.Constant):
                right = repr(node.comparators[0].value)
            elif isinstance(node.comparators[0], ast.Name):
                right = node.comparators[0].id
            else:
                right = "..."
            return f"{left} {op} {right}"

        return f"{left} ..."

    def _format_cmpop(self, op: ast.cmpop) -> str:
        """Format a comparison operator."""
        ops = {
            ast.Eq: "==",
            ast.NotEq: "!=",
            ast.Lt: "<",
            ast.LtE: "<=",
            ast.Gt: ">",
            ast.GtE: ">=",
            ast.Is: "is",
            ast.IsNot: "is not",
            ast.In: "in",
            ast.NotIn: "not in",
        }
        return ops.get(type(op), "?")

    def _get_pattern_str(self, pattern: ast.pattern) -> str:
        """Get a string representation of a match pattern."""
        if isinstance(pattern, ast.MatchValue):
            if isinstance(pattern.value, ast.Constant):
                return repr(pattern.value.value)
        elif isinstance(pattern, ast.MatchAs):
            if pattern.pattern is None:
                return f"_ as {pattern.name}" if pattern.name else "_"
            return f"{self._get_pattern_str(pattern.pattern)} as {pattern.name}"
        elif isinstance(pattern, ast.MatchOr):
            return " | ".join(self._get_pattern_str(p) for p in pattern.patterns)
        elif isinstance(pattern, ast.MatchSequence):
            return "[...]"
        elif isinstance(pattern, ast.MatchMapping):
            return "{...}"
        elif isinstance(pattern, ast.MatchClass):
            if isinstance(pattern.cls, ast.Name):
                return f"{pattern.cls.id}(...)"
        elif isinstance(pattern, ast.MatchStar):
            return f"*{pattern.name}" if pattern.name else "*_"
        return "..."
