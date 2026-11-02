"""Conservative intraprocedural census of row locks combined with eager joins."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class _Query:
    lock: int = 0
    related: bool = False


_States = frozenset[_Query]
_Environment = dict[str, _States]


def lock_join_lines(source: str) -> list[int]:  # noqa: C901, PLR0915  # AST dispatch and its scoped data-flow walkers.
    """Follow query chains, aliases, reassignment and branch alternatives within each scope.

    Projections and select_related(None) remove eager joins. Prefetches execute in
    separate statements. This is deliberately not an interprocedural ORM type checker.
    """
    lines: set[int] = set()

    def record(states: _States) -> None:
        lines.update(state.lock for state in states if state.lock and state.related)

    def expression(node: ast.AST | None, env: _Environment) -> _States:  # noqa: C901, PLR0911, PLR0912  # One case per AST expression shape.
        if isinstance(node, ast.Name):
            return env.get(node.id, frozenset({_Query()}))
        if isinstance(node, ast.Attribute):
            return expression(node.value, env)
        if isinstance(node, ast.IfExp):
            return expression(node.body, env) | expression(node.orelse, env)
        if isinstance(node, ast.Subscript):
            return expression(node.value, env)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                states = expression(node.func.value, env)
                method = node.func.attr
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    expression(arg, env)
                if method == "select_for_update":
                    return frozenset(replace(state, lock=node.lineno) for state in states)
                if method == "select_related":
                    related = not (len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value is None)
                    return frozenset(replace(state, related=related) for state in states)
                if method in {"values", "values_list", "count", "exists"}:
                    return frozenset(replace(state, related=False) for state in states)
                if method in {"get", "first", "last", "iterator", "aiterator", "aget", "afirst", "alast"}:
                    record(states)
                    return frozenset()
                return states
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                states = expression(arg, env)
                record(states)  # materialization or escape into another function
            # A queryset factory may be the root of a later method chain.
            return frozenset({_Query()})
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            local = env.copy()
            for generator in node.generators:
                record(expression(generator.iter, local))
                for condition in generator.ifs:
                    expression(condition, local)
            if isinstance(node, ast.DictComp):
                expression(node.key, local)
                expression(node.value, local)
            else:
                expression(node.elt, local)
            return frozenset()
        if node is not None:
            for child in ast.iter_child_nodes(node):
                expression(child, env)
        return frozenset()

    def merge(*branches: _Environment) -> _Environment:
        return {key: frozenset().union(*(branch.get(key, frozenset()) for branch in branches)) for key in set().union(*branches)}

    def block(body: list[ast.stmt], env: _Environment) -> _Environment:  # noqa: C901, PLR0912  # One case per statement control-flow shape.
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nested = block(node.body, env.copy())
                for states in nested.values():
                    record(states)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                states = expression(node.value, env)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = states
            elif isinstance(node, ast.If):
                record(expression(node.test, env))
                env = merge(block(node.body, env.copy()), block(node.orelse, env.copy()))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                record(expression(node.test if isinstance(node, ast.While) else node.iter, env))
                env = merge(env, block(node.body, env.copy()))
                env = block(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    expression(item.context_expr, env)
                env = block(node.body, env)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                env = merge(block(node.body, env.copy()), *(block(handler.body, env.copy()) for handler in node.handlers))
                env = block(node.finalbody, block(node.orelse, env))
            elif isinstance(node, (ast.Expr, ast.Return)):
                record(expression(node.value, env))
            else:
                expression(node, env)
        return env

    final = block(ast.parse(source).body, {})
    for states in final.values():
        record(states)
    return sorted(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scope", default="")
    parser.add_argument("--inventory", action="store_true")
    args = parser.parse_args()
    root = args.root / args.scope
    paths = sorted(path for path in root.rglob("*.py") if "migrations" not in path.parts)
    if not paths:
        raise ValueError(f"No Python source files found under {root}")
    count = 0
    for path in paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for line in lock_join_lines(source):
            functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and node.lineno <= line <= (node.end_lineno or node.lineno)]
            function = min(functions, key=lambda node: (node.end_lineno or node.lineno) - node.lineno).name if functions else "<module>"
            print(f"{path.relative_to(args.root)}:{line} {function}")
            count += 1
    print(f"{count} combined queries in {len(paths)} files")
    return 0 if args.inventory or count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
