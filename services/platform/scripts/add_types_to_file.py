#!/usr/bin/env python3
"""
Semi-Automated Type Addition Tool for PRAHO Platform - Enhanced Edition

AST-based analysis to identify missing type annotations and suggest appropriate types.
Specially designed for Django applications with Romanian business domain support.

Features:
- 🎯 Django pattern recognition (admin, views, templates, models)
- 🇷🇴 Romanian business type detection (CUI, VAT, invoices, domains)
- 🔄 Service layer patterns with Result types
- 📦 Smart import management for apps.common.types
- 🎨 Template tag/filter type detection
- ⚡ Auto-format integration with ruff
- 🤖 Interactive and automated modes

Part of Phase 2.4 developer tooling for type annotation migration.
"""

import argparse
import ast
import logging
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class TypeSuggestionEngine:
    """Engine for analyzing Python files and suggesting type annotations"""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.content = file_path.read_text(encoding="utf-8")
        self.lines = self.content.splitlines()
        self.tree: ast.AST | None = None
        self.suggestions: list[dict[str, Any]] = []
        self.django_imports: set[str] = set()
        self.existing_imports: set[str] = set()

        # Django pattern detector registry
        self._pattern_detectors = [
            self._detect_template_tag,
            self._detect_admin_display_method,
            self._detect_admin_short_description,
            self._detect_view_method,
            self._detect_class_based_view_method,
            self._detect_form_method,
            self._detect_model_method,
            self._detect_service_layer_method,
            self._detect_romanian_business_method,
            self._detect_repository_method,
        ]

    def parse_file(self) -> bool:
        """Parse the Python file into AST"""
        try:
            self.tree = ast.parse(self.content, filename=str(self.file_path))
            return True
        except SyntaxError as e:
            logger.error(f"Syntax error in {self.file_path}: {e}")
            return False

    def analyze_imports(self) -> None:
        """Analyze existing imports to understand available types"""
        if not self.tree:
            return

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.existing_imports.add(alias.name)
                    if "django" in alias.name:
                        self.django_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_name = f"{module}.{alias.name}" if module else alias.name
                    self.existing_imports.add(full_name)
                    if "django" in module:
                        self.django_imports.add(full_name)

    def detect_django_patterns(self, node: ast.FunctionDef) -> str | None:
        """Detect Django-specific patterns using pattern detector registry"""
        # Apply each detector in order until one returns a result
        for detector in self._pattern_detectors:
            result = detector(node)
            if result:
                return result

        return None

    def _detect_template_tag(self, node: ast.FunctionDef) -> str | None:
        """Detect Django template tag/filter patterns."""
        if self._is_template_tag_function(node):
            return self._get_template_tag_return_type(node)
        return None

    def _detect_admin_display_method(self, node: ast.FunctionDef) -> str | None:
        """Detect known Django admin display methods."""
        admin_display_methods = {
            "get_full_name": "str",
            "staff_role": "str",
            "primary_customer_name": "str",
            "two_factor_enabled": "str | bool",
            "is_staff_user": "str | bool",
            "format_invoice_number": "str",
            "format_cui": "str",
            "format_phone": "str",
            "format_currency": "str",
            "billing_status_display": "str",
            "payment_status_display": "str",
            "service_status_display": "str",
        }
        return admin_display_methods.get(node.name)

    def _detect_admin_short_description(self, node: ast.FunctionDef) -> str | None:
        """Detect Django admin methods with short_description attribute."""
        if any(
            "short_description" in getattr(stmt, "attr", "")
            for stmt in ast.walk(node)
            if isinstance(stmt, ast.Attribute)
        ):
            return "str"
        return None

    def _detect_view_method(self, node: ast.FunctionDef) -> str | None:
        """Detect Django view HTTP methods."""
        if node.name in ["get", "post", "put", "patch", "delete"]:
            return "HttpResponse"
        return None

    def _detect_class_based_view_method(self, node: ast.FunctionDef) -> str | None:
        """Detect Django Class-Based View method patterns."""
        cbv_methods = {
            "get_context_data": "dict[str, Any]",
            "get_initial": "dict[str, Any]",
            "get_success_url": "str",
            "get_absolute_url": "str",
            "dispatch": "HttpResponse",
            "get_queryset": "QuerySet[Any]",
        }

        if node.name in cbv_methods:
            return cbv_methods[node.name]

        if node.name.startswith("get_") and "context" in node.name:
            return "dict[str, Any]"

        return None

    def _detect_form_method(self, node: ast.FunctionDef) -> str | None:
        """Detect Django form method patterns."""
        if node.name == "clean" or node.name.startswith("clean_"):
            return "Any"
        if node.name == "save":
            return "Any"
        return None

    def _detect_model_method(self, node: ast.FunctionDef) -> str | None:
        """Detect Django model method patterns."""
        model_methods = {
            "__str__": "str",
            "get_absolute_url": "str",
        }
        return model_methods.get(node.name)

    def _detect_service_layer_method(self, node: ast.FunctionDef) -> str | None:
        """Detect service layer patterns."""
        if node.name.endswith("_service") or "service" in self.file_path.parts:
            return "Result[Any, str]"
        return None

    def _detect_romanian_business_method(self, node: ast.FunctionDef) -> str | None:
        """Detect PRAHO Romanian business patterns."""
        romanian_methods = {
            "validate_cui": "Result[CUIString, str]",
            "validate_vat": "Result[VATString, str]",
            "format_invoice_number": "InvoiceNumber",
            "generate_order_number": "OrderNumber",
            "calculate_vat": "dict[str, float]",
            "get_vat_rate": "float",
            "format_money": "str",
            "get_payment_reference": "PaymentReference",
            "validate_domain": "Result[DomainName, str]",
            "validate_email": "Result[EmailAddress, str]",
            "send_notification": "Result[bool, str]",
            "process_webhook": "Result[dict[str, Any], str]",
        }
        return romanian_methods.get(node.name)

    def _detect_repository_method(self, node: ast.FunctionDef) -> str | None:
        """Detect repository pattern methods."""
        if node.name.startswith("create_") or node.name.startswith("update_"):
            return "Result[Any, str]"
        elif node.name.startswith("delete_"):
            return "Result[bool, str]"
        elif node.name.startswith("find_"):
            return "Result[Any | None, str]"
        elif node.name.startswith("list_"):
            return "Result[list[Any], str]"
        return None

    def _is_template_tag_function(self, node: ast.FunctionDef) -> bool:
        """Check if function is a Django template tag or filter"""
        # Check for @register.filter or @register.simple_tag decorators
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Attribute):
                if (
                    isinstance(decorator.value, ast.Name)
                    and decorator.value.id == "register"
                    and decorator.attr in ("filter", "simple_tag", "inclusion_tag")
                ):
                    return True
            elif (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "register"
                and decorator.func.attr in ("filter", "simple_tag", "inclusion_tag")
            ):
                return True
        return False

    def _get_template_tag_return_type(self, node: ast.FunctionDef) -> str:
        """Get appropriate return type for Django template tags/filters"""
        # Analyze the function to determine return type
        for stmt in ast.walk(node):
            if (
                isinstance(stmt, ast.Return)
                and stmt.value
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Name)
            ):
                func_name = stmt.value.func.id
                if func_name == "mark_safe":
                    return "SafeString"  # Need to add import
                elif func_name == "format_html":
                    return "SafeString"
                elif func_name in ("escape", "str"):
                    return "str"

        # Default for template tags/filters
        return "str"

    def _suggest_django_types(self, arg_name: str) -> str | None:
        """Suggest Django-specific types"""
        if arg_name == "request":
            return "HttpRequest"
        elif arg_name == "queryset":
            return "QuerySet[Any]"
        return None

    def _suggest_business_domain_types(self, arg_name: str) -> str | None:
        """Suggest Romanian business domain types"""
        business_type_map = {
            "cui": "CUIString",
            "vat_number": "VATString",
            "email": "EmailAddress",
            "phone": "PhoneNumber",
            "domain": "DomainName",
            "invoice_number": "InvoiceNumber",
            "order_number": "OrderNumber",
            "amount": "Amount",
            "currency": "Currency",
        }
        return business_type_map.get(arg_name)

    def _suggest_common_types(self, arg_name: str) -> str | None:
        """Suggest common Python types based on patterns"""
        # Create pattern mappings to reduce branching
        exact_patterns = {
            "pk": "int",
            "template_name": "TemplateName",
        }

        multi_value_patterns = {
            ("name", "title", "description", "content", "message", "subject"): "str",
            ("data", "params", "kwargs", "context", "config"): "dict[str, Any]",
            ("css_class", "css_classes"): "CSSClass | CSSClasses",
        }

        # Check exact patterns first
        if arg_name in exact_patterns:
            return exact_patterns[arg_name]

        # Check multi-value patterns
        for pattern_group, type_hint in multi_value_patterns.items():
            if arg_name in pattern_group:
                return type_hint

        # Check prefix/suffix patterns with consolidated returns
        pattern_checks = [
            (arg_name.endswith("_id"), "int"),
            (arg_name.startswith(("is_", "has_", "can_")), "bool"),
            ("date" in arg_name or "time" in arg_name, "datetime"),
            (arg_name.endswith("s") and arg_name not in ("cls", "args", "address"), "list[Any]"),
        ]

        for condition, type_hint in pattern_checks:
            if condition:
                return type_hint

        return None

    def suggest_parameter_types(self, node: ast.FunctionDef) -> list[tuple[str, str]]:
        """Suggest types for function parameters based on names and context"""
        suggestions = []

        for arg in node.args.args:
            arg_name = arg.arg

            # Skip self and cls
            if arg_name in ("self", "cls"):
                continue

            # Skip if already has annotation
            if arg.annotation:
                continue

            # Try different type suggestion strategies
            suggested_type = (
                self._suggest_django_types(arg_name)
                or self._suggest_business_domain_types(arg_name)
                or self._suggest_common_types(arg_name)
            )

            if suggested_type:
                suggestions.append((arg_name, suggested_type))

        return suggestions

    def suggest_return_type(self, node: ast.FunctionDef) -> str | None:
        """Suggest return type based on function analysis using analyzers"""
        # Skip if already has return annotation
        if node.returns:
            return None

        # Try analyzers in order until one returns a result
        analyzers = [
            self._analyze_django_patterns,
            self._analyze_return_statements,
        ]

        for analyzer in analyzers:
            result = analyzer(node)
            if result:
                return result

        return "Any"  # Fallback for functions with no clear return pattern

    def _analyze_django_patterns(self, node: ast.FunctionDef) -> str | None:
        """Analyze Django-specific patterns first."""
        return self.detect_django_patterns(node)

    def _analyze_return_statements(self, node: ast.FunctionDef) -> str | None:
        """Analyze return statements to infer type."""
        return_types = set()

        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return):
                return_type = self._infer_return_type_from_statement(stmt)
                if return_type:
                    return_types.add(return_type)

        return self._combine_return_types(return_types)

    def _infer_return_type_from_statement(self, stmt: ast.Return) -> str | None:
        """Infer return type from a single return statement."""
        if stmt.value is None:
            return "None"

        # Type inference based on AST node type
        type_inferrers: dict[type[ast.expr], Callable[[ast.expr], str | None]] = {
            ast.Constant: lambda x: self._infer_constant_type(x) if isinstance(x, ast.Constant) else None,
            ast.Dict: lambda _: "dict[str, Any]",
            ast.List: lambda _: "list[Any]",
            ast.Call: lambda x: self._infer_call_type(x) if isinstance(x, ast.Call) else None,
        }

        inferrer = type_inferrers.get(type(stmt.value))
        return inferrer(stmt.value) if inferrer else None

    def _infer_constant_type(self, value: ast.Constant) -> str:
        """Infer type from constant values."""
        const_types = {
            str: "str",
            bool: "bool",
            int: "int",
            float: "float",
        }
        return const_types.get(type(value.value), "Any")

    def _infer_call_type(self, value: ast.Call) -> str | None:
        """Infer type from function calls."""
        if isinstance(value.func, ast.Name):
            func_name = value.func.id
            call_type_mapping = {
                "render": "HttpResponse",
                "redirect": "HttpResponse",
                "JsonResponse": "JsonResponse",
            }
            return call_type_mapping.get(func_name)
        return None

    def _combine_return_types(self, return_types: set[str]) -> str | None:
        """Combine multiple return types into a union or single type."""
        if not return_types:
            return None

        if len(return_types) == 1:
            return return_types.pop()

        if "None" in return_types:
            other_types = return_types - {"None"}
            if len(other_types) == 1:
                return f"{other_types.pop()} | None"
            elif len(other_types) > 1:
                return f"({' | '.join(sorted(other_types))}) | None"

        # Multiple return types - create union
        return " | ".join(sorted(return_types))

    def analyze_functions(self) -> None:
        """Analyze all function definitions and suggest types"""
        if not self.tree:
            return

        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                # Skip functions that already have complete annotations
                if self._has_complete_annotations(node):
                    continue

                suggestion = {
                    "type": "function",
                    "name": node.name,
                    "line": node.lineno,
                    "parameters": self.suggest_parameter_types(node),
                    "return_type": self.suggest_return_type(node),
                    "original_line": self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                }

                self.suggestions.append(suggestion)

    def _has_complete_annotations(self, node: ast.FunctionDef) -> bool:
        """Check if function already has complete type annotations"""
        if node.returns is None:
            return False  # Missing return annotation

        return all(not (arg.arg not in ("self", "cls") and arg.annotation is None) for arg in node.args.args)

    def generate_needed_imports(self) -> set[str]:
        """Generate the imports needed for suggested types"""
        needed_imports: set[str] = set()

        # Check what types are used in suggestions
        for suggestion in self.suggestions:
            if suggestion["return_type"]:
                self._check_type_imports(suggestion["return_type"], needed_imports)

            for _param_name, param_type in suggestion["parameters"]:
                self._check_type_imports(param_type, needed_imports)

        # Remove imports that already exist
        return needed_imports - self.existing_imports

    def _check_type_imports(self, type_str: str, needed_imports: set[str]) -> None:
        """Check what imports are needed for a type string"""
        # Django types
        if "HttpRequest" in type_str:
            needed_imports.add("django.http.HttpRequest")
        if "HttpResponse" in type_str:
            needed_imports.add("django.http.HttpResponse")
        if "JsonResponse" in type_str:
            needed_imports.add("django.http.JsonResponse")
        if "QuerySet" in type_str:
            needed_imports.add("django.db.models.QuerySet")
        if "SafeString" in type_str:
            needed_imports.add("django.utils.safestring.SafeString")

        # PRAHO common types - check if they're from apps.common.types
        romanian_types = {
            "Result",
            "CUIString",
            "VATString",
            "EmailAddress",
            "PhoneNumber",
            "DomainName",
            "InvoiceNumber",
            "OrderNumber",
            "ProformaNumber",
            "PaymentReference",
            "Amount",
            "Currency",
            "TemplateName",
            "CSSClass",
            "CSSClasses",
            "ValidationResult",
            "ServiceResult",
            "BusinessResult",
        }

        for romanian_type in romanian_types:
            if romanian_type in type_str:
                needed_imports.add(f"apps.common.types.{romanian_type}")

        # Standard library types
        if "datetime" in type_str:
            needed_imports.add("datetime")
        if "Any" in type_str:
            needed_imports.add("typing.Any")
        if "Decimal" in type_str:
            needed_imports.add("decimal.Decimal")

    def format_function_signature(self, suggestion: dict[str, Any]) -> str:
        """Format the complete function signature with suggested types"""
        original_line = suggestion["original_line"].strip()

        # Extract function definition parts
        match = re.match(r"^(\s*)(def\s+\w+\s*)\((.*?)\)(\s*:?\s*.*?)$", original_line)
        if not match:
            return original_line  # Can't parse, return original

        indent, func_part, params_part, rest_part = match.groups()

        # Parse existing parameters
        params = []
        if params_part.strip():
            # Simple parameter parsing (doesn't handle complex cases)
            for param_raw in params_part.split(","):
                param = param_raw.strip()
                if ":" in param:
                    # Already has type annotation
                    params.append(param)
                else:
                    # Check if we have a suggestion for this parameter
                    param_name = param.split("=")[0].strip()
                    suggested_type = None

                    for p_name, p_type in suggestion["parameters"]:
                        if p_name == param_name:
                            suggested_type = p_type
                            break

                    if suggested_type:
                        if "=" in param:  # Has default value
                            name_part, default_part = param.split("=", 1)
                            params.append(f"{name_part.strip()}: {suggested_type} = {default_part.strip()}")
                        else:
                            params.append(f"{param}: {suggested_type}")
                    else:
                        params.append(param)

        # Add return type annotation
        return_type = suggestion["return_type"]
        return_annotation = f" -> {return_type}:" if return_type and not rest_part.strip().startswith("->") else ":"

        # Reconstruct the function definition
        params_str = ", ".join(params)
        return f"{indent}{func_part}({params_str}){return_annotation}"

    def run_analysis(self) -> bool:
        """Run the complete analysis"""
        logger.info(f"Analyzing {self.file_path}")

        if not self.parse_file():
            return False

        self.analyze_imports()
        self.analyze_functions()

        return True


class InteractiveTypeAdder:
    """Interactive interface for reviewing and applying type suggestions"""

    def __init__(self, file_path: Path, dry_run: bool = False, format_after: bool = False):
        self.file_path = file_path
        self.dry_run = dry_run
        self.format_after = format_after
        self.engine = TypeSuggestionEngine(file_path)

    def _validate_analysis(self) -> bool:
        """Validate that analysis was successful and suggestions were found"""
        if not self.engine.run_analysis():
            logger.error("Failed to analyze file")
            return False

        if not self.engine.suggestions:
            logger.info("No type annotation suggestions found")
            return False

        logger.info(f"Found {len(self.engine.suggestions)} functions that could benefit from type annotations")
        return True

    def _display_needed_imports(self) -> set[str]:
        """Display needed imports and return the set"""
        needed_imports = self.engine.generate_needed_imports()
        if needed_imports:
            print("\n📦 The following imports will be needed:")
            for imp in sorted(needed_imports):
                print(f"  from {imp}")
            print()
        return needed_imports

    def _process_user_choice(self, choice: str, i: int, approved_changes: list, remaining_suggestions: list) -> str:
        """Process user choice and return action ('continue', 'break', 'add_all')"""
        if choice == "q":
            print("Quitting...")
            return "break"
        elif choice == "a":
            print("Applying all remaining changes...")
            approved_changes.extend(remaining_suggestions)
            return "break"
        elif choice == "y":
            approved_changes.append(self.engine.suggestions[i - 1])
            print("✅ Change approved")
            return "continue"
        else:
            print("❌ Change skipped")
            return "continue"

    def _process_suggestions_interactively(self) -> list:
        """Process suggestions interactively and return approved changes"""
        approved_changes = []

        for i, suggestion in enumerate(self.engine.suggestions, 1):
            print(f"\n--- Function {i}/{len(self.engine.suggestions)} ---")
            print(f"Function: {suggestion['name']} (line {suggestion['line']})")
            print(f"Current: {suggestion['original_line'].strip()}")

            new_signature = self.engine.format_function_signature(suggestion)
            print(f"Suggested: {new_signature}")

            if self.dry_run:
                print("✅ [DRY RUN] Would apply this change")
                approved_changes.append(suggestion)
            else:
                choice = input("\nApply this change? [y/N/q/a]: ").lower().strip()
                remaining_suggestions = self.engine.suggestions[i - 1 :]
                action = self._process_user_choice(choice, i, approved_changes, remaining_suggestions)

                if action == "break":
                    break

        return approved_changes

    def run(self) -> None:
        """Run the interactive type addition process"""
        # Validate analysis
        if not self._validate_analysis():
            return

        # Display needed imports
        needed_imports = self._display_needed_imports()

        # Process suggestions
        approved_changes = self._process_suggestions_interactively()

        # Apply changes
        if approved_changes:
            if self.dry_run:
                print(f"\n🔍 DRY RUN: Would apply {len(approved_changes)} changes")
            else:
                self._apply_changes(approved_changes, needed_imports)
                print(f"\n✅ Applied {len(approved_changes)} type annotations")
        else:
            print("\n🚫 No changes applied")

    def _apply_changes(self, changes: list[dict[str, Any]], needed_imports: set[str]) -> None:
        """Apply the approved changes to the file"""
        lines = self.engine.lines.copy()

        # Sort changes by line number in reverse order to avoid line number shifts
        changes.sort(key=lambda x: x["line"], reverse=True)

        # Apply function signature changes
        for change in changes:
            line_idx = change["line"] - 1
            if line_idx < len(lines):
                new_signature = self.engine.format_function_signature(change)
                lines[line_idx] = new_signature

        # Add needed imports (simplified - add at the top after existing imports)
        if needed_imports:
            # Find the last import line
            last_import_idx = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(("import ", "from ")) and not line.strip().startswith("#"):
                    last_import_idx = i

            # Add new imports
            import_lines = []
            for imp in sorted(needed_imports):
                if "." in imp:
                    module, name = imp.rsplit(".", 1)
                    import_lines.append(f"from {module} import {name}")
                else:
                    import_lines.append(f"import {imp}")

            # Insert after last import
            for i, import_line in enumerate(import_lines):
                lines.insert(last_import_idx + 1 + i, import_line)

        # Write back to file
        self.file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Format the file if requested
        if self.format_after:
            self._format_file()

    def _format_file(self) -> None:
        """Format the file using ruff"""
        try:
            import subprocess  # noqa: PLC0415

            result = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "ruff", "format", str(self.file_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                logger.info(f"✅ Formatted {self.file_path} with ruff")
            else:
                logger.warning(f"⚠️ ruff format failed: {result.stderr}")
        except FileNotFoundError:
            logger.warning("⚠️ ruff not found - skipping format")
        except Exception as e:
            logger.warning(f"⚠️ Failed to format file: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Semi-automated type addition tool for PRAHO Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s apps/users/admin.py                    # Interactive mode
  %(prog)s apps/users/admin.py --dry-run          # Preview changes only
  %(prog)s apps/users/admin.py --auto-approve     # Apply all suggestions automatically
  %(prog)s apps/users/admin.py --format           # Apply changes and format with ruff
  %(prog)s apps/users/admin.py --auto-approve --format  # Fully automated

The tool analyzes Python files and suggests type annotations based on:

🎯 DJANGO PATTERNS:
- Admin display methods: format_*, *_display -> str
- View methods: get, post, dispatch -> HttpResponse
- CBV methods: get_context_data -> dict[str, Any]
- Template tags/filters: @register.filter -> str/SafeString
- Model methods: __str__ -> str, get_absolute_url -> str

🇷🇴 ROMANIAN BUSINESS PATTERNS:
- validate_cui -> Result[CUIString, str]
- validate_vat -> Result[VATString, str]
- format_invoice_number -> InvoiceNumber
- calculate_vat -> dict[str, float]
- validate_email -> Result[EmailAddress, str]
- validate_domain -> Result[DomainName, str]
- send_notification -> Result[bool, str]
- process_webhook -> Result[dict[str, Any], str]

📋 PARAMETER TYPE DETECTION:
- cui -> CUIString, vat_number -> VATString
- email -> EmailAddress, phone -> PhoneNumber
- domain -> DomainName, invoice_number -> InvoiceNumber
- amount -> Amount, currency -> Currency
- request -> HttpRequest, queryset -> QuerySet[Any]
- is_*, has_*, can_* -> bool
- *_id, pk -> int

🔄 SERVICE LAYER PATTERNS:
- create_* -> Result[Any, str]
- update_* -> Result[Any, str]
- delete_* -> Result[bool, str]
- find_* -> Result[Any | None, str]
- list_* -> Result[list[Any], str]

All suggested types leverage the comprehensive PRAHO common/types.py type system
with Romanian business domain types and Result pattern for error handling.
""",
    )

    parser.add_argument("file", type=Path, help="Python file to analyze and add types to")

    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")

    parser.add_argument(
        "--auto-approve", action="store_true", help="Automatically apply all suggestions without prompting"
    )

    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument("--format", action="store_true", help="Auto-format the file after applying changes using ruff")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.file.exists():
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    if args.file.suffix != ".py":
        logger.error(f"Not a Python file: {args.file}")
        sys.exit(1)

    # Override dry_run if auto_approve is set
    dry_run = args.dry_run and not args.auto_approve

    adder = InteractiveTypeAdder(args.file, dry_run=dry_run, format_after=args.format)

    if args.auto_approve:
        # Patch the input function to always return 'a' (approve all)
        original_input = input

        def mock_input(prompt: str) -> str:
            print(prompt + " a")
            return "a"

        import builtins  # noqa: PLC0415

        builtins.input = mock_input  # type: ignore[assignment]

        try:
            adder.run()
        finally:
            builtins.input = original_input
    else:
        adder.run()


if __name__ == "__main__":
    main()
