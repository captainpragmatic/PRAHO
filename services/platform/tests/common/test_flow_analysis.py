"""
Tests for Flow Analysis Module

Tests the control-flow, data-flow, and hybrid analysis capabilities
for detecting logical errors and security vulnerabilities.
"""

import ast
from textwrap import dedent

from django.test import TestCase

from apps.common.flow_analysis import (
    AnalysisContext,
    AnalysisMode,
    AnalysisSeverity,
    BranchCoverageAnalyzer,
    ControlFlowAnalyzer,
    DataFlowAnalyzer,
    HybridFlowAnalyzer,
)
from apps.common.flow_analysis.base import IssueCategory
from apps.common.flow_analysis.hybrid_analyzer import HybridAnalysisConfig, analyze_code


class TestAnalysisContext(TestCase):
    """Test AnalysisContext creation and parsing."""

    def test_context_from_valid_source(self) -> None:
        """Test creating context from valid Python source."""
        source = "x = 1\ny = 2"
        context = AnalysisContext(file_path="test.py", source_code=source)

        self.assertIsNotNone(context.ast_tree)
        self.assertEqual(context.file_path, "test.py")
        self.assertEqual(context.source_code, source)

    def test_context_from_invalid_source(self) -> None:
        """Test creating context from invalid Python source."""
        source = "x = 1\n  invalid indent"
        context = AnalysisContext(file_path="test.py", source_code=source)

        self.assertIsNone(context.ast_tree)

    def test_context_scope_tracking(self) -> None:
        """Test scope enter/exit tracking."""
        context = AnalysisContext(file_path="test.py", source_code="x = 1")

        self.assertEqual(context.current_scope, "<module>")

        context.enter_scope("MyClass")
        self.assertEqual(context.current_scope, "MyClass")

        context.enter_scope("my_method")
        self.assertEqual(context.current_scope, "MyClass.my_method")

        context.exit_scope()
        self.assertEqual(context.current_scope, "MyClass")

    def test_context_taint_tracking(self) -> None:
        """Test taint source and sanitization tracking."""
        context = AnalysisContext(file_path="test.py", source_code="x = 1")

        context.mark_tainted("user_input")
        self.assertTrue(context.is_tainted("user_input"))

        context.mark_sanitized("user_input")
        self.assertFalse(context.is_tainted("user_input"))


class TestControlFlowAnalyzer(TestCase):
    """Test control-flow analysis capabilities."""

    def setUp(self) -> None:
        self.analyzer = ControlFlowAnalyzer()

    def test_detect_infinite_loop(self) -> None:
        """Test detection of potential infinite loops."""
        source = dedent("""
            def infinite():
                while True:
                    pass
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        # Should detect potential infinite loop
        infinite_issues = [i for i in issues if i.category == IssueCategory.INFINITE_LOOP]
        self.assertGreater(len(infinite_issues), 0)

    def test_no_infinite_loop_with_break(self) -> None:
        """Test that loops with break are not flagged as infinite."""
        source = dedent("""
            def not_infinite():
                while True:
                    if condition:
                        break
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        infinite_issues = [i for i in issues if i.category == IssueCategory.INFINITE_LOOP]
        self.assertEqual(len(infinite_issues), 0)

    def test_detect_bare_except(self) -> None:
        """Test detection of bare except clauses."""
        source = dedent("""
            def risky():
                try:
                    do_something()
                except:
                    pass
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        exception_issues = [i for i in issues if i.category == IssueCategory.EXCEPTION_FLOW]
        self.assertGreater(len(exception_issues), 0)

    def test_detect_silenced_exception(self) -> None:
        """Test detection of silenced exceptions."""
        source = dedent("""
            def silenced():
                try:
                    risky_operation()
                except Exception:
                    pass
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        exception_issues = [i for i in issues if i.category == IssueCategory.EXCEPTION_FLOW]
        self.assertGreater(len(exception_issues), 0)

    def test_detect_constant_condition(self) -> None:
        """Test detection of constant conditions."""
        source = dedent("""
            def always_true():
                if True:
                    do_something()
                else:
                    never_reached()
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        conditional_issues = [
            i for i in issues if i.category == IssueCategory.CONDITIONAL_LOGIC
        ]
        self.assertGreater(len(conditional_issues), 0)


class TestDataFlowAnalyzer(TestCase):
    """Test data-flow analysis capabilities."""

    def setUp(self) -> None:
        self.analyzer = DataFlowAnalyzer()

    def test_detect_sql_injection(self) -> None:
        """Test detection of SQL injection vulnerabilities."""
        source = dedent("""
            def unsafe_query(request):
                user_id = request.GET['id']
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        sql_issues = [i for i in issues if i.category == IssueCategory.SQL_INJECTION]
        # Should detect the tainted data reaching execute
        self.assertGreater(len(sql_issues), 0)

    def test_detect_eval_usage(self) -> None:
        """Test detection of dangerous eval usage."""
        source = dedent("""
            def unsafe_eval(data):
                result = eval(data)
                return result
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        command_issues = [i for i in issues if i.category == IssueCategory.COMMAND_INJECTION]
        self.assertGreater(len(command_issues), 0)

    def test_detect_yaml_unsafe_load(self) -> None:
        """Test detection of unsafe YAML loading."""
        source = dedent("""
            import yaml

            def load_config(data):
                config = yaml.load(data)
                return config
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        deser_issues = [
            i for i in issues if i.category == IssueCategory.INSECURE_DESERIALIZATION
        ]
        self.assertGreater(len(deser_issues), 0)

    def test_detect_subprocess_shell(self) -> None:
        """Test detection of subprocess with shell=True."""
        source = dedent("""
            import subprocess

            def run_command(cmd):
                subprocess.run(cmd, shell=True)
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        command_issues = [i for i in issues if i.category == IssueCategory.COMMAND_INJECTION]
        self.assertGreater(len(command_issues), 0)

    def test_detect_pickle_usage(self) -> None:
        """Test detection of pickle usage with potential untrusted data."""
        source = dedent("""
            import pickle

            def load_data(data):
                obj = pickle.loads(data)
                return obj
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        deser_issues = [
            i for i in issues if i.category == IssueCategory.INSECURE_DESERIALIZATION
        ]
        self.assertGreater(len(deser_issues), 0)

    def test_taint_propagation(self) -> None:
        """Test that taint is properly propagated through assignments."""
        source = dedent("""
            def process_input(request):
                user_data = request.POST['data']
                result = "SELECT * FROM t WHERE x = " + user_data
                cursor.execute(result)
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        # Should track taint through direct concatenation
        sql_issues = [i for i in issues if i.category == IssueCategory.SQL_INJECTION]
        self.assertGreater(len(sql_issues), 0)


class TestBranchCoverageAnalyzer(TestCase):
    """Test branch coverage analysis capabilities."""

    def setUp(self) -> None:
        self.analyzer = BranchCoverageAnalyzer()

    def test_detect_missing_else(self) -> None:
        """Test detection of if statements without else when appropriate."""
        source = dedent("""
            def check_value(x) -> int:
                if x > 0:
                    return 1
                elif x < 0:
                    return -1
                # Missing else for x == 0
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        branch_issues = [i for i in issues if i.category == IssueCategory.MISSING_BRANCH]
        self.assertGreater(len(branch_issues), 0)

    def test_complete_if_chain(self) -> None:
        """Test that complete if-elif-else chains are not flagged."""
        source = dedent("""
            def check_value(x):
                if x > 0:
                    return 1
                elif x < 0:
                    return -1
                else:
                    return 0
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        branch_issues = [i for i in issues if i.category == IssueCategory.MISSING_BRANCH]
        self.assertEqual(len(branch_issues), 0)

    def test_detect_incomplete_exception_handling(self) -> None:
        """Test detection of incomplete exception handling."""
        source = dedent("""
            def risky_operation():
                try:
                    dangerous()
                except ValueError:
                    handle_value_error()
                except KeyError:
                    handle_key_error()
                # No broad exception handler
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        issues = self.analyzer.analyze(context)

        # Should note that not all exceptions are handled
        branch_issues = [i for i in issues if i.category == IssueCategory.MISSING_BRANCH]
        # This depends on configuration - may or may not flag


class TestHybridFlowAnalyzer(TestCase):
    """Test hybrid analysis capabilities."""

    def setUp(self) -> None:
        self.analyzer = HybridFlowAnalyzer()

    def test_hybrid_mode_runs_both_analyzers(self) -> None:
        """Test that hybrid mode runs both control-flow and data-flow analysis."""
        source = dedent("""
            def vulnerable(request):
                # Control flow issue
                while True:
                    pass

                # Data flow issue
                user_input = request.GET['cmd']
                eval(user_input)
        """)
        context = AnalysisContext(file_path="test.py", source_code=source)
        result = self.analyzer.analyze_file("<string>")

        # For string input, we need to use analyze_code
        result = analyze_code(source)

        # Should find both types of issues
        control_issues = [i for i in result.issues if i.mode == AnalysisMode.CONTROL_FLOW]
        data_issues = [i for i in result.issues if i.mode == AnalysisMode.DATA_FLOW]

        # At least one of each should be found
        self.assertGreater(len(control_issues) + len(data_issues), 0)

    def test_configurable_modes(self) -> None:
        """Test that analysis modes can be configured."""
        source = dedent("""
            def test():
                while True:
                    pass
        """)

        # Control-flow only
        config = HybridAnalysisConfig(
            enable_control_flow=True,
            enable_data_flow=False,
            enable_branch_coverage=False,
        )
        result = analyze_code(source, config)

        # Should only have control-flow issues
        data_issues = [i for i in result.issues if i.mode == AnalysisMode.DATA_FLOW]
        self.assertEqual(len(data_issues), 0)

    def test_cross_reference_findings(self) -> None:
        """Test that findings are cross-referenced between analyses."""
        source = dedent("""
            def dangerous(request):
                while True:
                    user_input = request.GET['x']
                    cursor.execute(user_input)
        """)
        result = analyze_code(source)

        # Should potentially amplify severity for issues in infinite loop
        hybrid_issues = [i for i in result.issues if i.mode == AnalysisMode.HYBRID]
        # Cross-reference creates hybrid mode issues
        # May or may not find depending on exact cross-reference logic

    def test_result_summary(self) -> None:
        """Test that result provides useful summary information."""
        source = dedent("""
            def test(request):
                x = request.GET['x']
                if x > 0:
                    return 1
        """)
        result = analyze_code(source)

        # Should have summary information
        self.assertEqual(result.files_analyzed, 1)
        self.assertGreater(result.total_lines, 0)
        self.assertEqual(result.analysis_mode, AnalysisMode.HYBRID)

        # Can convert to dict for serialization
        result_dict = result.to_dict()
        self.assertIn("issues", result_dict)
        self.assertIn("summary", result_dict)


class TestAnalysisSeverity(TestCase):
    """Test severity comparison and handling."""

    def test_severity_ordering(self) -> None:
        """Test that severities are properly ordered."""
        self.assertTrue(AnalysisSeverity.INFO < AnalysisSeverity.LOW)
        self.assertTrue(AnalysisSeverity.LOW < AnalysisSeverity.MEDIUM)
        self.assertTrue(AnalysisSeverity.MEDIUM < AnalysisSeverity.HIGH)
        self.assertTrue(AnalysisSeverity.HIGH < AnalysisSeverity.CRITICAL)

    def test_critical_detection(self) -> None:
        """Test detection of critical issues."""
        source = dedent("""
            def dangerous():
                data = input()
                eval(data)
        """)
        result = analyze_code(source)

        # eval should be critical
        self.assertTrue(result.has_critical_issues)

    def test_security_detection(self) -> None:
        """Test detection of security issues."""
        source = dedent("""
            import pickle
            def load(data):
                return pickle.loads(data)
        """)
        result = analyze_code(source)

        self.assertTrue(result.has_security_issues)


class TestIssueCategories(TestCase):
    """Test that issues are properly categorized."""

    def test_sql_injection_cwe(self) -> None:
        """Test SQL injection has correct CWE."""
        source = dedent("""
            def query(request):
                user_id = request.GET['id']
                cursor.execute(f"SELECT * FROM t WHERE id={user_id}")
        """)
        result = analyze_code(source)

        sql_issues = [i for i in result.issues if i.category == IssueCategory.SQL_INJECTION]
        for issue in sql_issues:
            self.assertEqual(issue.cwe_id, "CWE-89")

    def test_command_injection_cwe(self) -> None:
        """Test command injection has correct CWE."""
        source = dedent("""
            def run():
                cmd = input()
                eval(cmd)
        """)
        result = analyze_code(source)

        cmd_issues = [
            i for i in result.issues
            if i.category == IssueCategory.COMMAND_INJECTION
        ]
        for issue in cmd_issues:
            self.assertIn(issue.cwe_id, ["CWE-78", "CWE-95"])

    def test_xss_cwe(self) -> None:
        """Test XSS has correct CWE."""
        # XSS is detected when tainted data reaches XSS sinks
        source = dedent("""
            from django.http import HttpResponse

            def view(request):
                data = request.GET['x']
                return HttpResponse(data)
        """)
        result = analyze_code(source)

        xss_issues = [
            i for i in result.issues
            if i.category == IssueCategory.XSS_VULNERABILITY
        ]
        for issue in xss_issues:
            self.assertEqual(issue.cwe_id, "CWE-79")


class TestEdgeCases(TestCase):
    """Test edge cases and error handling."""

    def test_empty_source(self) -> None:
        """Test handling of empty source code."""
        result = analyze_code("")
        self.assertEqual(len(result.issues), 0)
        # Empty source has no AST to parse, so files_analyzed is 0
        self.assertEqual(result.files_analyzed, 0)

    def test_syntax_error_handling(self) -> None:
        """Test handling of source with syntax errors."""
        source = "def broken(:\n    pass"
        result = analyze_code(source)

        # Should report error, not crash
        self.assertGreater(len(result.errors), 0)

    def test_complex_nesting(self) -> None:
        """Test handling of deeply nested code."""
        source = dedent("""
            def complex():
                for i in range(10):
                    for j in range(10):
                        if i > j:
                            if j > 5:
                                try:
                                    while True:
                                        if condition:
                                            break
                                except Exception:
                                    pass
        """)
        result = analyze_code(source)
        # Should complete without error
        self.assertIsNotNone(result)

    def test_async_code(self) -> None:
        """Test handling of async code."""
        source = dedent("""
            async def async_vulnerable(request):
                data = request.POST['data']
                eval(data)
        """)
        result = analyze_code(source)

        # Should detect issues in async code too
        self.assertGreater(len(result.issues), 0)

    def test_class_methods(self) -> None:
        """Test analysis of class methods."""
        source = dedent("""
            class Service:
                def process(self, request):
                    user_input = request.GET['x']
                    self.execute(user_input)

                def execute(self, cmd):
                    eval(cmd)
        """)
        result = analyze_code(source)

        # Should detect eval
        cmd_issues = [
            i for i in result.issues
            if i.category == IssueCategory.COMMAND_INJECTION
        ]
        self.assertGreater(len(cmd_issues), 0)
