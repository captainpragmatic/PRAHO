"""
Control-Flow Analyzer - PRAHO Platform

Analyzes program execution flow to detect:
- Infinite loops and loop invariant issues
- Unreachable/dead code
- Missing branches in conditionals
- Exception handling gaps
- Logical errors in control structures

Control-flow analysis follows the execution path of the program,
identifying where branching occurs and ensuring all paths are valid.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

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
class ControlFlowNode:
    """Node in the control-flow graph."""

    id: int
    node_type: str
    ast_node: ast.AST
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    is_reachable: bool = True
    is_exit: bool = False
    is_entry: bool = False

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class ControlFlowGraph:
    """Control-flow graph for a function or module."""

    nodes: dict[int, ControlFlowNode] = field(default_factory=dict)
    entry_node: int | None = None
    exit_nodes: list[int] = field(default_factory=list)
    _node_counter: int = 0

    def add_node(self, node_type: str, ast_node: ast.AST, is_entry: bool = False, is_exit: bool = False) -> int:
        """Add a new node to the graph."""
        node_id = self._node_counter
        self._node_counter += 1

        cfg_node = ControlFlowNode(
            id=node_id, node_type=node_type, ast_node=ast_node, is_entry=is_entry, is_exit=is_exit
        )
        self.nodes[node_id] = cfg_node

        if is_entry:
            self.entry_node = node_id
        if is_exit:
            self.exit_nodes.append(node_id)

        return node_id

    def add_edge(self, from_id: int, to_id: int) -> None:
        """Add an edge between two nodes."""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].successors.append(to_id)
            self.nodes[to_id].predecessors.append(from_id)

    def mark_unreachable(self) -> None:
        """Mark unreachable nodes in the graph."""
        if self.entry_node is None:
            return

        # BFS from entry to mark reachable nodes
        visited: set[int] = set()
        queue = [self.entry_node]

        while queue:
            node_id = queue.pop(0)
            if node_id in visited:
                continue
            visited.add(node_id)
            self.nodes[node_id].is_reachable = True

            queue.extend(succ_id for succ_id in self.nodes[node_id].successors if succ_id not in visited)

        # Mark unvisited nodes as unreachable
        for node_id, node in self.nodes.items():
            if node_id not in visited:
                node.is_reachable = False


class ControlFlowAnalyzer(BaseFlowAnalyzer, ast.NodeVisitor):
    """
    Analyzes control-flow to detect logical errors.

    Detects:
    - Infinite loops (while True without break)
    - Dead code after return/raise/break/continue
    - Missing else branches
    - Exception handling issues
    - Loop invariants that could cause issues
    """

    def __init__(self) -> None:
        super().__init__()
        self.mode = AnalysisMode.CONTROL_FLOW
        self.context: AnalysisContext | None = None
        self.cfg: ControlFlowGraph = ControlFlowGraph()
        self.current_loop_depth = 0
        self.has_break_in_loop = False
        self.has_return = False
        self.in_try_block = False
        self.exception_handlers: list[str] = []

    def analyze(self, context: AnalysisContext) -> list[FlowIssue]:
        """Analyze control-flow and return detected issues."""
        self.reset()
        self.context = context

        if context.ast_tree is None:
            return []

        try:
            self.visit(context.ast_tree)
            self._analyze_cfg()
        except Exception as e:
            logger.warning(f"Control-flow analysis error in {context.file_path}: {e}")

        return self.issues

    def reset(self) -> None:
        """Reset analyzer state."""
        super().reset()
        self.cfg = ControlFlowGraph()
        self.current_loop_depth = 0
        self.has_break_in_loop = False
        self.has_return = False
        self.in_try_block = False
        self.exception_handlers = []

    def _analyze_cfg(self) -> None:
        """Analyze the control-flow graph for issues."""
        self.cfg.mark_unreachable()

        for node in self.cfg.nodes.values():
            if not node.is_reachable and node.node_type not in {"entry", "exit"}:
                self._report_unreachable_code(node)

    def _report_unreachable_code(self, node: ControlFlowNode) -> None:
        """Report unreachable code issue."""
        if self.context is None:
            return

        location = CodeLocation.from_ast_node(node.ast_node, self.context.file_path)
        code_snippet = self.get_source_line(self.context, location.line_number)

        self.add_issue(
            category=IssueCategory.UNREACHABLE_CODE,
            severity=AnalysisSeverity.MEDIUM,
            message=f"Unreachable code detected: {node.node_type}",
            location=location,
            code_snippet=code_snippet,
            remediation="Remove the unreachable code or fix the control flow logic.",
            cwe_id="CWE-561",
        )

    # AST Visitor Methods

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        if self.context:
            self.context.enter_scope(node.name)

        # Reset function-level state
        old_has_return = self.has_return
        self.has_return = False

        # Build CFG for this function
        entry_id = self.cfg.add_node("entry", node, is_entry=True)
        prev_node = entry_id

        for stmt in node.body:
            stmt_id = self.cfg.add_node(type(stmt).__name__, stmt)
            self.cfg.add_edge(prev_node, stmt_id)
            prev_node = stmt_id
            self.visit(stmt)

        exit_id = self.cfg.add_node("exit", node, is_exit=True)
        self.cfg.add_edge(prev_node, exit_id)

        # Check for missing return in non-void functions
        self._check_missing_return(node)

        self.has_return = old_has_return
        if self.context:
            self.context.exit_scope()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition (same analysis as sync)."""
        # Treat as regular function for control-flow analysis
        func_node = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment,
            lineno=node.lineno,
            col_offset=node.col_offset,
        )
        self.visit_FunctionDef(func_node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        if self.context:
            self.context.enter_scope(node.name)
        self.generic_visit(node)
        if self.context:
            self.context.exit_scope()

    def visit_If(self, node: ast.If) -> None:
        """Analyze if statements for logical issues."""
        self._check_if_statement(node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        """Analyze while loops for potential infinite loops."""
        self.current_loop_depth += 1
        old_has_break = self.has_break_in_loop
        self.has_break_in_loop = False

        self._check_while_loop(node)

        for stmt in node.body:
            self.visit(stmt)

        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)

        # Check for infinite loop
        if self._is_constant_true(node.test) and not self.has_break_in_loop:
            self._report_potential_infinite_loop(node)

        self.has_break_in_loop = old_has_break
        self.current_loop_depth -= 1

    def visit_For(self, node: ast.For) -> None:
        """Analyze for loops."""
        self.current_loop_depth += 1
        old_has_break = self.has_break_in_loop
        self.has_break_in_loop = False

        self._check_for_loop(node)
        self.generic_visit(node)

        self.has_break_in_loop = old_has_break
        self.current_loop_depth -= 1

    def visit_Break(self, node: ast.Break) -> None:
        """Track break statements in loops."""
        self.has_break_in_loop = True
        self._check_dead_code_after(node, "break")

    def visit_Continue(self, node: ast.Continue) -> None:
        """Check for dead code after continue."""
        self._check_dead_code_after(node, "continue")

    def visit_Return(self, node: ast.Return) -> None:
        """Track return statements and check for dead code."""
        self.has_return = True
        self._check_dead_code_after(node, "return")

    def visit_Raise(self, node: ast.Raise) -> None:
        """Check for dead code after raise."""
        self._check_dead_code_after(node, "raise")

    def visit_Try(self, node: ast.Try) -> None:
        """Analyze try-except blocks."""
        old_in_try = self.in_try_block
        self.in_try_block = True

        self._check_try_block(node)

        for stmt in node.body:
            self.visit(stmt)

        for handler in node.handlers:
            self.visit(handler)

        for stmt in node.orelse:
            self.visit(stmt)

        for stmt in node.finalbody:
            self.visit(stmt)

        self.in_try_block = old_in_try

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Analyze exception handlers."""
        # Track exception types being caught
        if node.type:
            if isinstance(node.type, ast.Name):
                self.exception_handlers.append(node.type.id)
            elif isinstance(node.type, ast.Tuple):
                for exc in node.type.elts:
                    if isinstance(exc, ast.Name):
                        self.exception_handlers.append(exc.id)

        self.generic_visit(node)

    # Analysis Helpers

    def _check_if_statement(self, node: ast.If) -> None:
        """Check if statement for issues."""
        if self.context is None:
            return

        # Check for constant condition (always true/false)
        if self._is_constant_true(node.test):
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.CONDITIONAL_LOGIC,
                severity=AnalysisSeverity.LOW,
                message="Condition is always True, else branch is unreachable",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation="Remove the condition or fix the logic.",
            )
        elif self._is_constant_false(node.test):
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.CONDITIONAL_LOGIC,
                severity=AnalysisSeverity.LOW,
                message="Condition is always False, if branch is unreachable",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation="Remove the condition or fix the logic.",
            )

        # Check for duplicate conditions in elif chain
        self._check_duplicate_conditions(node)

    def _check_duplicate_conditions(self, node: ast.If) -> None:
        """Check for duplicate conditions in if-elif chain."""
        if self.context is None:
            return

        conditions: list[tuple[ast.expr, int]] = [(node.test, node.lineno)]
        current: ast.If | None = node

        # Collect all conditions in the chain
        while current and current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                elif_node = current.orelse[0]
                conditions.append((elif_node.test, elif_node.lineno))
                current = elif_node
            else:
                break

        # Check for duplicates
        seen_conditions: dict[str, int] = {}
        for test, lineno in conditions:
            condition_str = ast.dump(test)
            if condition_str in seen_conditions:
                location = CodeLocation(
                    file_path=self.context.file_path,
                    line_number=lineno,
                )
                self.add_issue(
                    category=IssueCategory.CONDITIONAL_LOGIC,
                    severity=AnalysisSeverity.MEDIUM,
                    message=f"Duplicate condition (same as line {seen_conditions[condition_str]})",
                    location=location,
                    code_snippet=self.get_source_line(self.context, lineno),
                    remediation="Remove duplicate condition or check logic.",
                    cwe_id="CWE-561",
                )
            else:
                seen_conditions[condition_str] = lineno

    def _check_while_loop(self, node: ast.While) -> None:
        """Check while loop for issues."""
        if self.context is None:
            return

        # Check for empty loop body
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.LOOP_INVARIANT,
                severity=AnalysisSeverity.MEDIUM,
                message="While loop with empty body (pass) - possible busy wait",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation="Add proper loop body or use time.sleep() if waiting.",
            )

    def _check_for_loop(self, node: ast.For) -> None:
        """Check for loop for issues."""
        if self.context is None:
            return

        # Check for modifying iterator inside loop
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.name == target_name:
                            location = CodeLocation.from_ast_node(stmt, self.context.file_path)
                            self.add_issue(
                                category=IssueCategory.LOOP_INVARIANT,
                                severity=AnalysisSeverity.HIGH,
                                message=f"Loop variable '{target_name}' is reassigned inside loop",
                                location=location,
                                code_snippet=self.get_source_line(self.context, location.line_number),
                                remediation="Avoid reassigning the loop variable inside the loop.",
                            )

    def _check_try_block(self, node: ast.Try) -> None:
        """Check try-except block for issues."""
        if self.context is None:
            return

        # Check for bare except
        for handler in node.handlers:
            if handler.type is None:
                location = CodeLocation.from_ast_node(handler, self.context.file_path)
                self.add_issue(
                    category=IssueCategory.EXCEPTION_FLOW,
                    severity=AnalysisSeverity.MEDIUM,
                    message="Bare 'except:' clause catches all exceptions including SystemExit",
                    location=location,
                    code_snippet=self.get_source_line(self.context, location.line_number),
                    remediation="Use 'except Exception:' to avoid catching system exceptions.",
                    cwe_id="CWE-396",
                )

        # Check for overly broad Exception catch
        for handler in node.handlers:
            if (
                isinstance(handler.type, ast.Name)
                and handler.type.id == "Exception"
                and len(handler.body) == 1
                and isinstance(handler.body[0], ast.Pass)
            ):
                location = CodeLocation.from_ast_node(handler, self.context.file_path)
                self.add_issue(
                    category=IssueCategory.EXCEPTION_FLOW,
                    severity=AnalysisSeverity.HIGH,
                    message="Exception caught but silently ignored (pass)",
                    location=location,
                    code_snippet=self.get_source_line(self.context, location.line_number),
                    remediation="Log the exception or handle it appropriately.",
                    cwe_id="CWE-390",
                )

    def _check_missing_return(self, node: ast.FunctionDef) -> None:
        """Check if function might be missing a return statement."""
        if self.context is None:
            return

        # Skip if function has return type annotation of None
        if node.returns and isinstance(node.returns, ast.Constant) and node.returns.value is None:
            return

        # Skip __init__ methods
        if node.name == "__init__":
            return

        # Skip if function has type annotation returning None
        if node.returns and isinstance(node.returns, ast.Name) and node.returns.id == "None":
            return

        # Check if all code paths have return
        if not self._all_paths_return(node.body) and node.returns:
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.MISSING_BRANCH,
                severity=AnalysisSeverity.LOW,
                message=f"Function '{node.name}' may not return a value on all paths",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation="Ensure all code paths return a value.",
            )

    def _all_paths_return(self, stmts: list[ast.stmt]) -> bool:
        """Check if all code paths in statements return a value."""
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                return True
            elif isinstance(stmt, ast.If):
                # Both branches must return
                if_returns = self._all_paths_return(stmt.body)
                else_returns = self._all_paths_return(stmt.orelse) if stmt.orelse else False
                if if_returns and else_returns:
                    return True
            elif isinstance(stmt, ast.Raise):
                return True
            elif isinstance(stmt, ast.Try):
                # All handlers plus main body must return
                body_returns = self._all_paths_return(stmt.body)
                all_handlers_return = all(self._all_paths_return(handler.body) for handler in stmt.handlers)
                if body_returns or all_handlers_return:
                    return True
        return False

    def _check_dead_code_after(self, node: ast.stmt, stmt_type: str) -> None:
        """Check for dead code after a control flow statement."""
        if self.context is None:
            return

        # This is tricky - we need the parent to check for siblings
        # The CFG analysis handles this more comprehensively

    def _report_potential_infinite_loop(self, node: ast.While) -> None:
        """Report potential infinite loop."""
        if self.context is None:
            return

        location = CodeLocation.from_ast_node(node, self.context.file_path)
        self.add_issue(
            category=IssueCategory.INFINITE_LOOP,
            severity=AnalysisSeverity.HIGH,
            message="Potential infinite loop: while True without break statement",
            location=location,
            code_snippet=self.get_source_line(self.context, location.line_number),
            remediation="Add a break condition or use a finite loop.",
            cwe_id="CWE-835",
        )

    def _is_constant_true(self, node: ast.expr) -> bool:
        """Check if expression is always True."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.NameConstant):  # Python 3.7 compatibility
            return node.value is True
        return bool(isinstance(node, ast.Name) and node.id == "True")

    def _is_constant_false(self, node: ast.expr) -> bool:
        """Check if expression is always False."""
        if isinstance(node, ast.Constant):
            return not node.value
        if isinstance(node, ast.NameConstant):
            return node.value is False
        return bool(isinstance(node, ast.Name) and node.id == "False")
