"""
Flow Analysis Module - PRAHO Platform

Comprehensive control-flow and data-flow analysis for detecting:
- Logical errors in loops and conditionals (control-flow)
- Security vulnerabilities like injection attacks (data-flow)
- Unchecked branches and dead code
- Data leakage and taint propagation

The module alternates between control-flow and data-flow analysis modes
for thorough code examination.
"""

from apps.common.flow_analysis.base import (
    AnalysisContext,
    AnalysisMode,
    AnalysisResult,
    AnalysisSeverity,
    CodeLocation,
    FlowIssue,
)
from apps.common.flow_analysis.branch_coverage import BranchCoverageAnalyzer
from apps.common.flow_analysis.control_flow import ControlFlowAnalyzer
from apps.common.flow_analysis.data_flow import DataFlowAnalyzer
from apps.common.flow_analysis.hybrid_analyzer import HybridFlowAnalyzer

__all__ = [
    # Base types
    "AnalysisContext",
    "AnalysisMode",
    "AnalysisResult",
    "AnalysisSeverity",
    "CodeLocation",
    "FlowIssue",
    # Analyzers
    "BranchCoverageAnalyzer",
    "ControlFlowAnalyzer",
    "DataFlowAnalyzer",
    "HybridFlowAnalyzer",
]
