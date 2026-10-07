"""Guard swallowed signal database failures with boundaries inside each try."""

from __future__ import annotations

import ast
import io
import tokenize
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "services/platform/apps"
BASELINE = ROOT / "scripts/signal_isolation_baseline.txt"
MARKER = "# signal-isolation:"


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_TRIES = (ast.Try, ast.TryStar)
_BOUNDARIES = {"atomic", "best_effort_atomic"}
_DB_ERRORS = {
    "Error",
    "DatabaseError",
    "OperationalError",
    "ProgrammingError",
    "IntegrityError",
    "DataError",
    "InternalError",
    "NotSupportedError",
    "InterfaceError",
    "TransactionManagementError",
}
_READS = {"get", "exists", "count", "first", "last"}
_WRITES = {"create", "update", "get_or_create", "update_or_create"}
_QUERY_METHODS = {
    "filter",
    "exclude",
    "all",
    "using",
    "select_related",
    "prefetch_related",
    "order_by",
    "values",
    "values_list",
    "select_for_update",
    "distinct",
    "annotate",
    "alias",
    "none",
}
_NON_DB = {"cache", "default_storage", "logger", "logging", "kwargs", "dict", "metadata", "details", "params"}
_NON_DB_ATTRIBUTES = {
    "meta",
    "metadata",
    "old_terms",
    "target_terms",
    "renewal_terms",
    "META",
    "GET",
    "POST",
    "session",
    "headers",
}


def _nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Walk executable syntax, leaving nested functions and lambdas for their own scope."""
    yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, (*_FUNCTIONS, ast.Lambda)):
            yield from _nodes(child)


class _Scope:
    def __init__(self, tree: ast.Module, owner: ast.AST, *, queries: set[str] | None = None) -> None:
        self.aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else (alias.name.split(".")[0])
                    )
        self.queries = set(queries or ())
        self.non_db = set(_NON_DB)
        assignments = [node for node in _nodes(owner) if isinstance(node, (ast.Assign, ast.AnnAssign))]
        for node in assignments:
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(value, (ast.Dict, ast.DictComp, ast.List, ast.ListComp, ast.Set, ast.SetComp, ast.Tuple)):
                self.non_db.update(target.id for target in targets if isinstance(target, ast.Name))
        # A queryset can be assigned, then chained through several local aliases.
        for _ in assignments:
            for node in assignments:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if node.value is not None and self.query(node.value):
                    self.queries.update(target.id for target in targets if isinstance(target, ast.Name))

    def name(self, expr: ast.expr) -> str:
        if isinstance(expr, ast.Name):
            return self.aliases.get(expr.id, expr.id)
        if isinstance(expr, ast.Attribute):
            return f"{self.name(expr.value)}.{expr.attr}"
        return ""

    def non_database(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id in {"dict", "list", "set"}:
            return True
        if isinstance(expr, ast.Name):
            name = self.name(expr)
            return expr.id in self.non_db or name.startswith(("django.core.cache.", "django.core.files.storage."))
        if isinstance(expr, ast.Attribute):
            return expr.attr in _NON_DB_ATTRIBUTES or self.non_database(expr.value)
        return isinstance(expr, (ast.Dict, ast.List, ast.Set, ast.Tuple, ast.Constant))

    def query(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
            return self.query(expr.value)
        if isinstance(expr, ast.Name):
            return expr.id in self.queries or expr.id in {"qs", "queryset"}
        if isinstance(expr, ast.Attribute):
            return expr.attr in {"objects", "all_objects", "_default_manager", "_base_manager"} or self.query(
                expr.value
            )
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            return self.query(expr.func.value) or (
                expr.func.attr in _QUERY_METHODS and not self.non_database(expr.func.value)
            )
        return False

    def boundary(self, expr: ast.expr, *, decorator: bool = False) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        name = self.name(expr.func)
        kind = name.rsplit(".", 1)[-1]
        if decorator:
            return kind == "best_effort_atomic"
        if kind not in _BOUNDARIES:
            return False
        if kind == "atomic":
            if name not in {"atomic", "transaction.atomic", "django.db.transaction.atomic"}:
                return False
            savepoint = next(
                (keyword.value for keyword in expr.keywords if keyword.arg == "savepoint"),
                expr.args[1] if len(expr.args) > 1 else ast.Constant(value=True),
            )
            return isinstance(savepoint, ast.Constant) and savepoint.value is True
        return True

    def swallowing(self, handler: ast.ExceptHandler) -> bool:
        if handler.type is None:
            return True
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        database_errors = _DB_ERRORS | {
            f"{module}.{kind}"
            for module in ("django.db", "django.db.utils", "django.db.transaction")
            for kind in _DB_ERRORS
        }
        return any(self.name(expr) in {"Exception", "BaseException"} | database_errors for expr in types)

    def database_call(self, node: ast.Call) -> bool:
        func = node.func
        name = self.name(func)
        if name.rsplit(".", 1)[-1].startswith("log_") and not (
            isinstance(func, ast.Attribute) and self.non_database(func.value)
        ):
            return True
        if isinstance(func, ast.Attribute):
            if any(part.endswith("AuditService") for part in self.name(func.value).split(".")):
                return True
            if self.non_database(func.value):
                return False
            if func.attr in {"save", "delete"}:
                return True
            return (func.attr in _READS and (self.query(func.value) or isinstance(func.value, ast.Attribute))) or (
                (func.attr in _WRITES or func.attr.startswith("bulk_")) and self.query(func.value)
            )
        return False


def _outcomes(body: list[ast.stmt]) -> set[str]:
    """A conditional or nested raise alone must not exempt a swallowing path."""
    outcomes = {"fall"}
    for stmt in body:
        if "fall" not in outcomes:
            break
        following = {"fall"}
        if isinstance(stmt, ast.Raise):
            following = {"raise"}
        elif isinstance(stmt, (ast.Return, ast.Break, ast.Continue)):
            following = {"exit"}
        elif isinstance(stmt, ast.If):
            following = _outcomes(stmt.body) | _outcomes(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            following = _outcomes(stmt.body)
        outcomes = (outcomes - {"fall"}) | following
    return outcomes


class _DatabaseVisitor(ast.NodeVisitor):
    def __init__(
        self,
        scope: _Scope,
        helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        tree: ast.Module,
        *,
        protected: bool = False,
        depth: int = 0,
    ) -> None:
        self.scope = scope
        self.helpers = helpers
        self.tree = tree
        self.protected = protected
        self.depth = depth
        self.unsafe = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        # Context-manager expressions execute before their own boundary is entered.
        previous = self.protected
        for item in node.items:
            self.visit(item.context_expr)
            self.protected = self.protected or self.scope.boundary(item.context_expr)
        for stmt in node.body:
            self.visit(stmt)
        self.protected = previous

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> None:
        helper = self.helpers.get(node.func.id) if isinstance(node.func, ast.Name) else None
        if not self.protected and self.depth == 0 and helper is not None:
            parameters = [*helper.args.posonlyargs, *helper.args.args]
            bindings = {parameter.arg: argument for parameter, argument in zip(parameters, node.args, strict=False)}
            keyword_parameters = {parameter.arg for parameter in [*helper.args.args, *helper.args.kwonlyargs]}
            bindings.update(
                (keyword.arg, keyword.value)
                for keyword in node.keywords
                if keyword.arg is not None and keyword.arg in keyword_parameters
            )
            scope = _Scope(
                self.tree,
                helper,
                queries={name for name, argument in bindings.items() if self.scope.query(argument)},
            )
            visitor = _DatabaseVisitor(
                scope,
                self.helpers,
                self.tree,
                protected=any(scope.boundary(item, decorator=True) for item in helper.decorator_list),
                depth=1,
            )
            for stmt in helper.body:
                visitor.visit(stmt)
            self.unsafe = self.unsafe or visitor.unsafe
        elif not self.protected and self.scope.database_call(node):
            self.unsafe = True
        if isinstance(node.func, ast.Name) and node.func.id in {"list", "bool", "len"}:
            for arg in node.args:
                self._evaluate(arg)
        self.generic_visit(node)

    def _evaluate(self, expr: ast.expr) -> None:
        if not self.protected and self.scope.query(expr):
            self.unsafe = True
        self.visit(expr)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # A plain slice stays lazy; indexing and slices with a step evaluate.
        if not isinstance(node.slice, ast.Slice) or (
            node.slice.step is not None
            and not (isinstance(node.slice.step, ast.Constant) and node.slice.step.value is None)
        ):
            self._evaluate(node.value)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self._evaluate(node.test)
        for stmt in [*node.body, *node.orelse]:
            self.visit(stmt)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self._evaluate(node.iter)
        for stmt in [*node.body, *node.orelse]:
            self.visit(stmt)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self._evaluate(node.iter)
        for condition in node.ifs:
            self.visit(condition)


def find_unisolated_handlers(source: str, *, include_marked: bool = False) -> list[int]:
    tree = ast.parse(source)
    helpers = {node.name: node for node in tree.body if isinstance(node, _FUNCTIONS)}
    module_scope = _Scope(tree, tree)
    callbacks = {
        arg.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and module_scope.name(node.func).endswith(".on_commit")
        for arg in [*node.args, *(keyword.value for keyword in node.keywords if keyword.arg == "func")]
        if isinstance(arg, ast.Name)
    }
    comments = {
        token.start[0]: token.string
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT
    }
    found: list[int] = []
    owners = [tree, *(node for node in ast.walk(tree) if isinstance(node, _FUNCTIONS))]
    for owner in owners:
        if isinstance(owner, _FUNCTIONS) and owner.name in callbacks:
            continue
        scope = _Scope(tree, owner)
        decorated = isinstance(owner, _FUNCTIONS) and any(
            scope.boundary(item, decorator=True) for item in owner.decorator_list
        )
        for node in _nodes(owner):
            if not isinstance(node, _TRIES):
                continue
            visitor = _DatabaseVisitor(scope, helpers, tree, protected=decorated)
            for stmt in node.body:
                visitor.visit(stmt)
            if not visitor.unsafe:
                continue
            for handler in node.handlers:
                comment = comments.get(handler.lineno, "")
                marked = MARKER in comment and bool(comment.split(MARKER, 1)[1].strip())
                if (
                    scope.swallowing(handler)
                    and _outcomes(handler.body) != {"raise"}
                    and (include_marked or not marked)
                ):
                    found.append(handler.lineno)
    return sorted(set(found))


def _signal_sources() -> list[Path]:
    return sorted({*APP_ROOT.glob("*/signals.py"), *APP_ROOT.glob("*/*_signals.py")})


def _baseline_entries(source: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in source.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        site, separator, reason = line.partition(" | ")
        if not separator or not reason.strip() or site in entries:
            raise ValueError(f"Invalid or duplicate signal-isolation baseline entry: {line}")
        entries[site] = reason.strip()
    return entries


class SignalHandlerIsolationTests(SimpleTestCase):
    def test_repository_signal_handlers_are_isolated(self) -> None:
        sources = _signal_sources()
        self.assertEqual(len(sources), 16)
        self.assertIn(APP_ROOT / "provisioning/virtualmin_signals.py", sources)
        self.assertIn(APP_ROOT / "billing/custom_signals.py", sources)
        self.assertIn(APP_ROOT / "provisioning/signals.py", sources)
        unmarked: list[str] = []
        exceptions: dict[str, str] = {}
        for path in sources:
            source = path.read_text(encoding="utf-8")
            unmarked.extend(f"{path.relative_to(ROOT)}:{line}" for line in find_unisolated_handlers(source))
            for line in find_unisolated_handlers(source, include_marked=True):
                if line not in find_unisolated_handlers(source):
                    exceptions[f"{path.relative_to(ROOT)}:{line}"] = (
                        source.splitlines()[line - 1].split(MARKER, 1)[1].strip()
                    )
        self.assertEqual(
            unmarked,
            [],
            "Swallowed signal DB failures need a boundary inside their try:\n" + "\n".join(unmarked),
        )
        self.assertTrue(BASELINE.is_file(), "The signal-isolation ratchet baseline must be checked in.")
        baseline = _baseline_entries(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(exceptions, baseline, "Remove stale entries; baseline every justified inline exception.")

    def test_catch_inside_atomic_is_flagged(self) -> None:
        source = "with transaction.atomic():\n    try:\n        instance.save()\n    except Exception:\n        pass\n"
        self.assertEqual(find_unisolated_handlers(source), [4])

    def test_catch_outside_savepoint_passes(self) -> None:
        source = "try:\n    with transaction.atomic():\n        instance.save()\nexcept Exception:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [])

    def test_reraising_handler_passes(self) -> None:
        source = "try:\n    instance.save()\nexcept Exception:\n    raise\n"
        self.assertEqual(find_unisolated_handlers(source), [])

    def test_swallow_application_errors_requires_inner_savepoint(self) -> None:
        source = dedent(
            """
            try:
                with swallow_application_errors(logger=logger):
                    instance.save()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(source), [4])
        isolated = source.replace(
            "        instance.save()",
            "        with transaction.atomic():\n            instance.save()",
        )
        self.assertEqual(find_unisolated_handlers(isolated), [])

    def test_atomic_without_savepoint_is_flagged(self) -> None:
        for boundary in (
            "transaction.atomic(savepoint=False)",
            "transaction.atomic(None, False)",
            "savepoint(savepoint=False)",
        ):
            with self.subTest(boundary=boundary):
                source = (
                    "from django.db.transaction import atomic as savepoint\n"
                    f"try:\n    with {boundary}:\n        instance.save()\nexcept Exception:\n    pass\n"
                )
                self.assertEqual(find_unisolated_handlers(source), [5])
                isolated = source.replace("False", "True")
                self.assertEqual(find_unisolated_handlers(isolated), [])

    def test_queryset_evaluation_and_aliases_are_flagged(self) -> None:
        operations = (
            "rows[0]",
            "list(rows[:2])",
            "rows[::2]",
            "bool(rows)",
            "len(rows)",
            "if rows:\n        consume(rows)",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                source = (
                    "query = Model.objects.filter(active=True)\n"
                    "rows = query\n"
                    f"try:\n    {operation}\nexcept Exception:\n    pass\n"
                )
                expected = 4 + len(operation.splitlines())
                self.assertEqual(find_unisolated_handlers(source), [expected])
                isolated = source.replace(
                    f"    {operation}",
                    "    with transaction.atomic():\n"
                    + "\n".join("        " + line for line in operation.splitlines()),
                )
                self.assertEqual(find_unisolated_handlers(isolated), [])
        lazy = "rows = Model.objects.filter(active=True)\ntry:\n    limited = rows[:2]\nexcept Exception:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(lazy), [])

    def test_database_exception_subclasses_and_aliases_are_flagged(self) -> None:
        exceptions = (
            "OperationalError",
            "ProgrammingError",
            "IntegrityError",
            "DataError",
            "InternalError",
            "NotSupportedError",
            "InterfaceError",
        )
        for exception in exceptions:
            for module in ("django.db", "django.db.utils"):
                for catch, imports in (
                    (exception, ""),
                    ("DBFailure", f"from {module} import {exception} as DBFailure\n"),
                    (f"db.{exception}", f"import {module} as db\n"),
                ):
                    with self.subTest(exception=exception, module=module, catch=catch):
                        source = imports + f"try:\n    instance.save()\nexcept {catch}:\n    pass\n"
                        self.assertEqual(find_unisolated_handlers(source), [3 + len(imports.splitlines())])
                        self.assertEqual(find_unisolated_handlers(source.replace("    pass", "    raise")), [])

    def test_keyword_helper_arguments_and_aliases_are_resolved(self) -> None:
        for parameters in ("rows", "*, rows"):
            with self.subTest(parameters=parameters):
                source = (
                    f"def evaluate({parameters}):\n"
                    "    alias = rows\n"
                    "    list(alias)\n"
                    "try:\n"
                    "    evaluate(rows=Model.objects.filter(active=True))\n"
                    "except Exception:\n"
                    "    pass\n"
                )
                self.assertEqual(find_unisolated_handlers(source), [6])
                isolated = source.replace(
                    "    list(alias)",
                    "    with transaction.atomic():\n        list(alias)",
                )
                self.assertEqual(find_unisolated_handlers(isolated), [])

    def test_unmarked_offender_is_flagged(self) -> None:
        source = "try:\n    instance.save()\nexcept Exception:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [3])

    def test_marker_passes_and_remains_visible_to_ratchet(self) -> None:
        source = "try:\n    instance.save()\nexcept Exception:  # signal-isolation: deliberate fixture\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [])
        self.assertEqual(find_unisolated_handlers(source, include_marked=True), [3])
        blank = source.replace("deliberate fixture", "")
        self.assertEqual(find_unisolated_handlers(blank), [3])
        string_marker = 'try:\n    instance.save()\nexcept Exception:\n    note = "# signal-isolation: not a comment"\n'
        self.assertEqual(find_unisolated_handlers(string_marker), [3])

    def test_one_level_helper_is_resolved(self) -> None:
        source = "def write():\n    instance.save()\ntry:\n    write()\nexcept Exception:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [5])
        safe = dedent(
            """
            def write():
                with best_effort_atomic(logger=logger):
                    instance.save()
            try:
                write()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(safe), [])
        second_level = dedent(
            """
            def write():
                instance.save()
            def helper():
                write()
            try:
                helper()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(second_level), [])

    def test_on_commit_lambda_and_named_callback_are_skipped(self) -> None:
        source = "try:\n    transaction.on_commit(lambda: Model.objects.create())\nexcept Exception:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [])
        callback = dedent(
            """
            def deferred():
                try:
                    instance.save()
                except Exception:
                    pass
            transaction.on_commit(deferred)
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(callback), [])
        self.assertEqual(
            find_unisolated_handlers(callback.replace("transaction.on_commit(deferred)", "deferred()")), [4]
        )

    def test_best_effort_context_and_decorator_pass(self) -> None:
        source = dedent(
            """
            try:
                with best_effort_atomic(logger=logger):
                    instance.save()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(source), [])
        decorated = dedent(
            """
            @best_effort_atomic(logger=logger)
            def receiver():
                try:
                    instance.save()
                except Exception:
                    pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(decorated), [])

    def test_reads_writes_audits_and_log_functions_are_flagged(self) -> None:
        operations = (
            "Model.objects.get(pk=1)",
            "Model.all_objects.get(pk=1)",
            "instance.children.get(pk=1)",
            "instance.children.exists()",
            "instance.children.count()",
            "instance.children.first()",
            "instance.children.last()",
            "Model.objects.exists()",
            "Model.objects.count()",
            "Model.objects.first()",
            "Model.objects.last()",
            "instance.save()",
            "instance.delete()",
            "Model.objects.create()",
            "Model.objects.filter(active=True).update(active=False)",
            "Model.objects.exclude(active=True).delete()",
            "Model.objects.bulk_create([])",
            "Model.objects.bulk_update([], [])",
            "Model.objects.get_or_create(pk=1)",
            "Model.objects.update_or_create(pk=1)",
            "BillingAuditService.log_event()",
            "services.CustomAuditService.record()",
            "log_security_event()",
            "events.log_event()",
            "list(Model.objects.filter(active=True))",
            "list(Model.objects.exclude(active=True))",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                source = f"try:\n    {operation}\nexcept Exception:\n    pass\n"
                self.assertEqual(find_unisolated_handlers(source), [3])

    def test_queryset_aliases_and_iteration_are_flagged(self) -> None:
        cases = (
            "rows = Model.objects.filter(active=True)\ntry:\n    list(rows)\nexcept Exception:\n    pass\n",
            dedent(
                """
                rows = Model.objects.exclude(active=True)
                try:
                    for row in rows:
                        consume(row)
                except Exception:
                    pass
                """
            ).lstrip(),
            "try:\n    [row.pk for row in Model.objects.filter(active=True)]\nexcept Exception:\n    pass\n",
            dedent(
                """
                rows = Model.objects.filter(active=True)
                alias = rows
                try:
                    alias.update(active=False)
                except Exception:
                    pass
                """
            ).lstrip(),
            "rows = Model.objects.filter(active=True)\ntry:\n    rows.last()\nexcept Exception:\n    pass\n",
        )
        for source, expected in zip(cases, ([4], [5], [3], [5], [4]), strict=True):
            with self.subTest(source=source):
                self.assertEqual(find_unisolated_handlers(source), expected)
        escaped = dedent(
            """
            with transaction.atomic():
                rows = Model.objects.filter(active=True)
            try:
                list(rows)
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(escaped), [5])

    def test_lazy_queries_dict_cache_storage_and_logger_are_not_db_calls(self) -> None:
        source = dedent("""
            try:
                rows = Model.objects.filter(active=True).exclude(pk=1)
                data = {}
                data.update(active=True)
                data.get("active")
                instance.meta.get("active")
                cache.delete("key")
                default_storage.exists("path")
                default_storage.delete("path")
                logger.log_event("event")
            except Exception:
                pass
        """).lstrip()
        self.assertEqual(find_unisolated_handlers(source), [])

    def test_database_exception_aliases_bare_catches_and_partial_reraises(self) -> None:
        source = "from django.db import Error as DBFailure\ntry:\n    instance.save()\nexcept DBFailure:\n    pass\n"
        self.assertEqual(find_unisolated_handlers(source), [4])
        for catch in ("", "Exception", "DatabaseError", "Error", "IntegrityError", "(IntegrityError, ValueError)"):
            with self.subTest(catch=catch):
                source = f"try:\n    instance.save()\nexcept {catch}:\n    pass\n"
                self.assertEqual(find_unisolated_handlers(source), [3])
        partial = "try:\n    instance.save()\nexcept Exception:\n    if fatal:\n        raise\n"
        self.assertEqual(find_unisolated_handlers(partial), [3])
        nested = "try:\n    instance.save()\nexcept Exception:\n    def other():\n        raise\n"
        self.assertEqual(find_unisolated_handlers(nested), [3])

    def test_every_database_call_needs_its_own_inner_boundary(self) -> None:
        source = dedent(
            """
            try:
                with transaction.atomic():
                    instance.save()
                Model.objects.last()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(source), [5])
        for boundary in ("best_effort_atomic", "swallow_application_errors"):
            with self.subTest(boundary=boundary):
                inside = (
                    f"with {boundary}(logger=logger):\n"
                    "    try:\n        instance.save()\n    except Exception:\n        pass\n"
                )
                self.assertEqual(find_unisolated_handlers(inside), [4])
        aliased = dedent(
            """
            from django.db.transaction import atomic as savepoint
            try:
                with savepoint():
                    instance.save()
            except Exception:
                pass
            """
        ).lstrip()
        self.assertEqual(find_unisolated_handlers(aliased), [])

    def test_baseline_rejects_blank_reasons_and_duplicates(self) -> None:
        self.assertEqual(find_unisolated_handlers("pass\n"), [])
        entry = "services/platform/apps/example/signals.py:3 | required exception"
        self.assertEqual(_baseline_entries("# Empty by default\n"), {})
        self.assertEqual(_baseline_entries(entry), {entry.partition(" | ")[0]: "required exception"})
        for malformed in (entry.partition(" | ")[0], entry.partition(" | ")[0] + " | ", entry + "\n" + entry):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                _baseline_entries(malformed)
