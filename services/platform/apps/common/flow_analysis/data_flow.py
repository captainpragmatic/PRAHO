"""
Data-Flow Analyzer - PRAHO Platform

Tracks how data moves through the system to detect:
- SQL injection vulnerabilities
- XSS (Cross-Site Scripting) vulnerabilities
- Command injection
- Path traversal attacks
- Tainted data propagation
- Sensitive data leakage
- Insecure deserialization

Data-flow analysis follows variables from sources (user input) to sinks
(dangerous operations), identifying missing sanitization.
"""

from __future__ import annotations

import ast
import logging
import re
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


# Taint sources - functions/attributes that introduce user input
TAINT_SOURCES = {
    # Django request attributes
    "request.GET",
    "request.POST",
    "request.body",
    "request.data",  # DRF
    "request.query_params",  # DRF
    "request.FILES",
    "request.COOKIES",
    "request.META",
    "request.headers",
    "request.path",
    "request.path_info",
    # Form data
    "cleaned_data",
    "form.data",
    "self.cleaned_data",
    # Raw input
    "input",
    "raw_input",
    "sys.stdin",
    # Environment
    "os.environ",
    "os.getenv",
    # File operations
    "open",
    "file.read",
    "file.readline",
    "file.readlines",
}

# Taint source function calls
TAINT_SOURCE_FUNCS = {
    "input",
    "raw_input",
    "getattr",  # When used with request
    "json.loads",
    "json.load",
    "yaml.load",
    "yaml.safe_load",
    "pickle.loads",
    "pickle.load",
    "eval",
    "exec",
}

# Sanitization functions that make data safe
SANITIZERS = {
    # Django escaping
    "escape",
    "mark_safe",  # Actually marks as safe, need context
    "format_html",
    "escapejs",
    "strip_tags",
    "html.escape",
    # Validation
    "validate",
    "clean",
    "is_valid",
    "full_clean",
    # Type conversion (partial sanitization)
    "int",
    "float",
    "bool",
    # String sanitization
    "quote",
    "quote_plus",
    "urlencode",
    # Custom validators
    "validate_email",
    "validate_slug",
    "validate_unicode_slug",
}

# SQL injection sinks
SQL_SINKS = {
    "execute",
    "executemany",
    "raw",
    "extra",
    "RawSQL",
    "cursor.execute",
    "connection.execute",
}

# XSS sinks - places where data is rendered
XSS_SINKS = {
    "HttpResponse",
    "render",
    "render_to_string",
    "format_html",
    "mark_safe",
    "SafeString",
    "innerHTML",  # In case of JS analysis
}

# Command injection sinks
COMMAND_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "commands.getoutput",
    "commands.getstatusoutput",
    "popen",
    "popen2",
    "popen3",
    "popen4",
}

# Path traversal sinks
PATH_SINKS = {
    "open",
    "file",
    "os.path.join",
    "pathlib.Path",
    "shutil.copy",
    "shutil.move",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.makedirs",
    "os.mkdir",
}

# Insecure deserialization sinks
DESERIALIZATION_SINKS = {
    "pickle.loads",
    "pickle.load",
    "yaml.load",  # Without Loader
    "yaml.unsafe_load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
    "jsonpickle.decode",
}

# Sensitive data patterns
SENSITIVE_PATTERNS = [
    r"password",
    r"passwd",
    r"secret",
    r"api_key",
    r"apikey",
    r"auth_token",
    r"access_token",
    r"private_key",
    r"credit_card",
    r"ssn",
    r"social_security",
    r"bank_account",
]


@dataclass
class TaintedVariable:
    """Represents a tainted variable in the data flow."""

    name: str
    source: str  # Where the taint originated
    location: CodeLocation
    propagated_from: str | None = None  # If tainted through assignment
    is_sanitized: bool = False
    sanitizer: str | None = None


@dataclass
class DataFlowPath:
    """A path from source to sink."""

    source_var: str
    source_location: CodeLocation
    sink_func: str
    sink_location: CodeLocation
    intermediate_vars: list[str] = field(default_factory=list)
    is_sanitized: bool = False


class DataFlowAnalyzer(BaseFlowAnalyzer, ast.NodeVisitor):
    """
    Analyzes data-flow to detect security vulnerabilities.

    Tracks tainted data from sources (user input) through the program
    to sinks (dangerous operations), identifying missing sanitization.
    """

    def __init__(self) -> None:
        super().__init__()
        self.mode = AnalysisMode.DATA_FLOW
        self.context: AnalysisContext | None = None
        self.tainted_vars: dict[str, TaintedVariable] = {}
        self.data_flow_paths: list[DataFlowPath] = []
        self.current_assignment_target: str | None = None
        self.in_format_string = False

    def analyze(self, context: AnalysisContext) -> list[FlowIssue]:
        """Analyze data-flow and return detected issues."""
        self.reset()
        self.context = context

        if context.ast_tree is None:
            return []

        try:
            self.visit(context.ast_tree)
            self._analyze_taint_propagation()
        except Exception as e:
            logger.warning(f"Data-flow analysis error in {context.file_path}: {e}")

        return self.issues

    def reset(self) -> None:
        """Reset analyzer state."""
        super().reset()
        self.tainted_vars = {}
        self.data_flow_paths = []
        self.current_assignment_target = None
        self.in_format_string = False

    def _analyze_taint_propagation(self) -> None:
        """Analyze taint propagation paths for vulnerabilities."""
        for path in self.data_flow_paths:
            if not path.is_sanitized:
                self._report_taint_path(path)

    def _report_taint_path(self, path: DataFlowPath) -> None:
        """Report a tainted data path to a sink."""
        if self.context is None:
            return

        # Determine the category based on sink
        category = self._categorize_sink(path.sink_func)
        severity = self._get_sink_severity(category)
        cwe_id = self._get_cwe_for_category(category)

        message = f"Tainted data from '{path.source_var}' reaches sink '{path.sink_func}' " f"without sanitization"
        if path.intermediate_vars:
            message += f" (via: {' -> '.join(path.intermediate_vars)})"

        self.add_issue(
            category=category,
            severity=severity,
            message=message,
            location=path.sink_location,
            code_snippet=self.get_source_line(self.context, path.sink_location.line_number),
            remediation=self._get_remediation(category),
            cwe_id=cwe_id,
            metadata={
                "source_var": path.source_var,
                "source_line": path.source_location.line_number,
                "sink_func": path.sink_func,
                "intermediate_vars": path.intermediate_vars,
            },
        )

    def _categorize_sink(self, sink_func: str) -> IssueCategory:
        """Categorize the sink type."""
        if sink_func in SQL_SINKS or "execute" in sink_func.lower():
            return IssueCategory.SQL_INJECTION
        elif sink_func in XSS_SINKS:
            return IssueCategory.XSS_VULNERABILITY
        elif sink_func in COMMAND_SINKS:
            return IssueCategory.COMMAND_INJECTION
        elif sink_func in PATH_SINKS:
            return IssueCategory.PATH_TRAVERSAL
        elif sink_func in DESERIALIZATION_SINKS:
            return IssueCategory.INSECURE_DESERIALIZATION
        else:
            return IssueCategory.TAINTED_DATA

    def _get_sink_severity(self, category: IssueCategory) -> AnalysisSeverity:
        """Get severity based on vulnerability category."""
        severity_map = {
            IssueCategory.SQL_INJECTION: AnalysisSeverity.CRITICAL,
            IssueCategory.COMMAND_INJECTION: AnalysisSeverity.CRITICAL,
            IssueCategory.INSECURE_DESERIALIZATION: AnalysisSeverity.CRITICAL,
            IssueCategory.XSS_VULNERABILITY: AnalysisSeverity.HIGH,
            IssueCategory.PATH_TRAVERSAL: AnalysisSeverity.HIGH,
            IssueCategory.TAINTED_DATA: AnalysisSeverity.MEDIUM,
        }
        return severity_map.get(category, AnalysisSeverity.MEDIUM)

    def _get_cwe_for_category(self, category: IssueCategory) -> str:
        """Get CWE ID for vulnerability category."""
        cwe_map = {
            IssueCategory.SQL_INJECTION: "CWE-89",
            IssueCategory.XSS_VULNERABILITY: "CWE-79",
            IssueCategory.COMMAND_INJECTION: "CWE-78",
            IssueCategory.PATH_TRAVERSAL: "CWE-22",
            IssueCategory.INSECURE_DESERIALIZATION: "CWE-502",
            IssueCategory.TAINTED_DATA: "CWE-20",
        }
        return cwe_map.get(category, "CWE-20")

    def _get_remediation(self, category: IssueCategory) -> str:
        """Get remediation advice for vulnerability category."""
        remediations = {
            IssueCategory.SQL_INJECTION: (
                "Use parameterized queries or Django ORM instead of raw SQL. "
                "Never concatenate user input into SQL strings."
            ),
            IssueCategory.XSS_VULNERABILITY: (
                "Use Django's automatic escaping or escape user input with escape(). "
                "Avoid mark_safe() on user-controlled data."
            ),
            IssueCategory.COMMAND_INJECTION: (
                "Avoid shell commands with user input. Use subprocess with shell=False "
                "and pass arguments as a list. Validate and sanitize all input."
            ),
            IssueCategory.PATH_TRAVERSAL: (
                "Validate file paths against a whitelist. Use os.path.basename() "
                "to strip directory components. Never trust user-provided paths."
            ),
            IssueCategory.INSECURE_DESERIALIZATION: (
                "Never deserialize untrusted data with pickle/yaml. "
                "Use yaml.safe_load() instead of yaml.load(). Prefer JSON for data exchange."
            ),
            IssueCategory.TAINTED_DATA: (
                "Validate and sanitize all user input before use. " "Apply appropriate encoding for the context."
            ),
        }
        return remediations.get(category, "Validate and sanitize user input.")

    # AST Visitor Methods

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition, tracking parameters as potential taint sources."""
        if self.context:
            self.context.enter_scope(node.name)

        # Check for request parameter (common in Django views)
        for arg in node.args.args:
            arg_name = arg.arg
            if arg_name == "request":
                self._mark_request_tainted(node)
            elif arg_name in ("data", "form_data", "user_input", "payload"):
                # Mark suspicious parameter names as tainted
                if self.context:
                    location = CodeLocation.from_ast_node(arg, self.context.file_path)
                    self.tainted_vars[arg_name] = TaintedVariable(
                        name=arg_name,
                        source=f"function parameter: {arg_name}",
                        location=location,
                    )

        self.generic_visit(node)

        if self.context:
            self.context.exit_scope()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function (same analysis as sync)."""
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

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments for taint propagation."""
        if self.context is None:
            self.generic_visit(node)
            return

        # Get target name(s)
        for target in node.targets:
            target_name = self._get_name(target)
            if target_name:
                self.current_assignment_target = target_name

                # Check if RHS is tainted
                if self._is_tainted_expression(node.value):
                    source_var = self._get_taint_source(node.value)
                    location = CodeLocation.from_ast_node(node, self.context.file_path)

                    self.tainted_vars[target_name] = TaintedVariable(
                        name=target_name,
                        source=f"propagated from {source_var}",
                        location=location,
                        propagated_from=source_var,
                    )

                # Check if RHS introduces new taint
                elif self._is_taint_source(node.value):
                    source_name = self._get_source_name(node.value)
                    location = CodeLocation.from_ast_node(node, self.context.file_path)

                    self.tainted_vars[target_name] = TaintedVariable(
                        name=target_name,
                        source=source_name,
                        location=location,
                    )

                # Check if RHS sanitizes tainted data
                elif self._is_sanitizer(node.value):
                    if target_name in self.tainted_vars:
                        sanitizer = self._get_sanitizer_name(node.value)
                        self.tainted_vars[target_name].is_sanitized = True
                        self.tainted_vars[target_name].sanitizer = sanitizer

        self.current_assignment_target = None
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for taint sinks."""
        if self.context is None:
            self.generic_visit(node)
            return

        func_name = self._get_call_name(node)

        # Check if this is a dangerous sink
        if self._is_sink(func_name):
            # Check if any argument is tainted
            for arg in node.args:
                if self._is_tainted_expression(arg):
                    source_var = self._get_taint_source(arg)
                    if source_var and source_var in self.tainted_vars:
                        tainted = self.tainted_vars[source_var]
                        if not tainted.is_sanitized:
                            sink_location = CodeLocation.from_ast_node(node, self.context.file_path)
                            path = DataFlowPath(
                                source_var=source_var,
                                source_location=tainted.location,
                                sink_func=func_name,
                                sink_location=sink_location,
                                intermediate_vars=self._get_propagation_chain(source_var),
                                is_sanitized=False,
                            )
                            self.data_flow_paths.append(path)

            # Check keyword arguments
            for kw in node.keywords:
                if self._is_tainted_expression(kw.value):
                    source_var = self._get_taint_source(kw.value)
                    if source_var and source_var in self.tainted_vars:
                        tainted = self.tainted_vars[source_var]
                        if not tainted.is_sanitized:
                            sink_location = CodeLocation.from_ast_node(node, self.context.file_path)
                            path = DataFlowPath(
                                source_var=source_var,
                                source_location=tainted.location,
                                sink_func=func_name,
                                sink_location=sink_location,
                                intermediate_vars=self._get_propagation_chain(source_var),
                                is_sanitized=False,
                            )
                            self.data_flow_paths.append(path)

        # Check for dangerous patterns
        self._check_dangerous_calls(node, func_name)

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Analyze f-strings for potential injection."""
        if self.context is None:
            self.generic_visit(node)
            return

        self.in_format_string = True

        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if self._is_tainted_expression(value.value):
                    source_var = self._get_taint_source(value.value)
                    if source_var and source_var in self.tainted_vars:
                        tainted = self.tainted_vars[source_var]
                        if not tainted.is_sanitized:
                            location = CodeLocation.from_ast_node(node, self.context.file_path)
                            self.add_issue(
                                category=IssueCategory.TAINTED_DATA,
                                severity=AnalysisSeverity.MEDIUM,
                                message=f"Tainted variable '{source_var}' used in f-string",
                                location=location,
                                code_snippet=self.get_source_line(self.context, location.line_number),
                                remediation=(
                                    "Sanitize the variable before use in f-string, "
                                    "or use proper escaping for the context."
                                ),
                                cwe_id="CWE-116",
                            )

        self.in_format_string = False
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Track subscript access that could be taint sources."""
        if self.context is None:
            self.generic_visit(node)
            return

        # Check for request.GET['key'] or request.POST['key'] patterns
        subscript_str = self._get_subscript_string(node)
        if any(source in subscript_str for source in TAINT_SOURCES):
            if self.current_assignment_target:
                location = CodeLocation.from_ast_node(node, self.context.file_path)
                self.tainted_vars[self.current_assignment_target] = TaintedVariable(
                    name=self.current_assignment_target,
                    source=subscript_str,
                    location=location,
                )

        self.generic_visit(node)

    def _mark_request_tainted(self, node: ast.FunctionDef) -> None:
        """Mark request-related variables as tainted in a view function."""
        if self.context is None:
            return

        # The request parameter itself is tainted
        location = CodeLocation.from_ast_node(node, self.context.file_path)

        # Common request attributes are tainted
        for attr in ["GET", "POST", "body", "data", "COOKIES", "FILES", "META"]:
            var_name = f"request.{attr}"
            self.tainted_vars[var_name] = TaintedVariable(
                name=var_name,
                source="Django request object",
                location=location,
            )

    def _is_tainted_expression(self, node: ast.expr) -> bool:
        """Check if an expression contains tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Attribute):
            attr_name = self._get_attribute_chain(node)
            return attr_name in self.tainted_vars or any(attr_name.startswith(t) for t in self.tainted_vars)
        elif isinstance(node, ast.Subscript):
            subscript_str = self._get_subscript_string(node)
            return any(source in subscript_str for source in TAINT_SOURCES)
        elif isinstance(node, ast.BinOp):
            # String concatenation propagates taint
            return self._is_tainted_expression(node.left) or self._is_tainted_expression(node.right)
        elif isinstance(node, ast.Call):
            # Check if function returns tainted data
            for arg in node.args:
                if self._is_tainted_expression(arg):
                    return True
        return False

    def _is_taint_source(self, node: ast.expr) -> bool:
        """Check if expression is a taint source."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            return func_name in TAINT_SOURCE_FUNCS or any(source in func_name for source in TAINT_SOURCES)
        elif isinstance(node, ast.Subscript):
            subscript_str = self._get_subscript_string(node)
            return any(source in subscript_str for source in TAINT_SOURCES)
        elif isinstance(node, ast.Attribute):
            attr_chain = self._get_attribute_chain(node)
            return attr_chain in TAINT_SOURCES or any(source in attr_chain for source in TAINT_SOURCES)
        return False

    def _is_sanitizer(self, node: ast.expr) -> bool:
        """Check if expression is a sanitizer."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            return func_name in SANITIZERS or any(s in func_name for s in SANITIZERS)
        return False

    def _is_sink(self, func_name: str) -> bool:
        """Check if function is a dangerous sink."""
        all_sinks = SQL_SINKS | XSS_SINKS | COMMAND_SINKS | PATH_SINKS | DESERIALIZATION_SINKS
        return func_name in all_sinks or any(sink in func_name for sink in all_sinks)

    def _get_taint_source(self, node: ast.expr) -> str | None:
        """Get the name of the tainted variable in an expression."""
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return node.id
        elif isinstance(node, ast.Attribute):
            attr_name = self._get_attribute_chain(node)
            if attr_name in self.tainted_vars:
                return attr_name
            # Check for partial matches
            for tainted_var in self.tainted_vars:
                if attr_name.startswith(tainted_var):
                    return tainted_var
        elif isinstance(node, ast.Subscript):
            return self._get_subscript_string(node)
        elif isinstance(node, ast.BinOp):
            left = self._get_taint_source(node.left)
            if left:
                return left
            return self._get_taint_source(node.right)
        return None

    def _get_propagation_chain(self, var_name: str) -> list[str]:
        """Get the chain of variables through which taint propagated."""
        chain: list[str] = []
        current = var_name

        while current and current in self.tainted_vars:
            tainted = self.tainted_vars[current]
            if tainted.propagated_from:
                chain.append(tainted.propagated_from)
                current = tainted.propagated_from
            else:
                break

        return list(reversed(chain))

    def _check_dangerous_calls(self, node: ast.Call, func_name: str) -> None:
        """Check for dangerous function call patterns."""
        if self.context is None:
            return

        # Check for eval/exec with any arguments
        if func_name in {"eval", "exec"}:
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.COMMAND_INJECTION,
                severity=AnalysisSeverity.CRITICAL,
                message=f"Use of dangerous function '{func_name}'",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation=f"Avoid using {func_name}(). Use safer alternatives like ast.literal_eval().",
                cwe_id="CWE-95",
            )

        # Check for yaml.load without Loader
        if func_name == "yaml.load":
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                location = CodeLocation.from_ast_node(node, self.context.file_path)
                self.add_issue(
                    category=IssueCategory.INSECURE_DESERIALIZATION,
                    severity=AnalysisSeverity.CRITICAL,
                    message="yaml.load() without Loader parameter is vulnerable to code execution",
                    location=location,
                    code_snippet=self.get_source_line(self.context, location.line_number),
                    remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                    cwe_id="CWE-502",
                )

        # Check for pickle operations
        if "pickle" in func_name and any(op in func_name for op in ["load", "loads"]):
            location = CodeLocation.from_ast_node(node, self.context.file_path)
            self.add_issue(
                category=IssueCategory.INSECURE_DESERIALIZATION,
                severity=AnalysisSeverity.HIGH,
                message="Pickle deserialization can execute arbitrary code",
                location=location,
                code_snippet=self.get_source_line(self.context, location.line_number),
                remediation="Avoid pickle for untrusted data. Use JSON or other safe formats.",
                cwe_id="CWE-502",
            )

        # Check for subprocess with shell=True
        if "subprocess" in func_name:
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        location = CodeLocation.from_ast_node(node, self.context.file_path)
                        self.add_issue(
                            category=IssueCategory.COMMAND_INJECTION,
                            severity=AnalysisSeverity.HIGH,
                            message="subprocess with shell=True is vulnerable to command injection",
                            location=location,
                            code_snippet=self.get_source_line(self.context, location.line_number),
                            remediation="Use shell=False and pass command as a list.",
                            cwe_id="CWE-78",
                        )

        # Check for SQL raw queries
        if func_name in {"raw", "extra"} or "execute" in func_name:
            # Check if query uses string formatting with tainted data
            for arg in node.args:
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    if self._contains_tainted_data(arg):
                        location = CodeLocation.from_ast_node(node, self.context.file_path)
                        self.add_issue(
                            category=IssueCategory.SQL_INJECTION,
                            severity=AnalysisSeverity.CRITICAL,
                            message="SQL query built with string formatting and tainted data",
                            location=location,
                            code_snippet=self.get_source_line(self.context, location.line_number),
                            remediation="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', [user_id])",
                            cwe_id="CWE-89",
                        )

    def _contains_tainted_data(self, node: ast.expr) -> bool:
        """Check if an expression contains tainted data anywhere."""
        for child in ast.walk(node):
            if isinstance(child, ast.expr) and self._is_tainted_expression(child):
                return True
        return False

    # Helper methods for name extraction

    def _get_name(self, node: ast.expr) -> str | None:
        """Get the name from an expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_chain(node)
        elif isinstance(node, ast.Subscript):
            return self._get_subscript_string(node)
        return None

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attribute_chain(node.func)
        return ""

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get the full attribute chain as a string."""
        parts: list[str] = [node.attr]
        current: ast.expr = node.value

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))

    def _get_subscript_string(self, node: ast.Subscript) -> str:
        """Get a string representation of a subscript."""
        base = self._get_name(node.value) or ""
        if isinstance(node.slice, ast.Constant):
            return f"{base}[{node.slice.value!r}]"
        elif isinstance(node.slice, ast.Name):
            return f"{base}[{node.slice.id}]"
        return f"{base}[...]"

    def _get_source_name(self, node: ast.expr) -> str:
        """Get a descriptive name for a taint source."""
        if isinstance(node, ast.Call):
            return f"call to {self._get_call_name(node)}()"
        elif isinstance(node, ast.Subscript):
            return self._get_subscript_string(node)
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_chain(node)
        return "unknown source"

    def _get_sanitizer_name(self, node: ast.expr) -> str:
        """Get the name of the sanitizer function."""
        if isinstance(node, ast.Call):
            return self._get_call_name(node)
        return "unknown sanitizer"
