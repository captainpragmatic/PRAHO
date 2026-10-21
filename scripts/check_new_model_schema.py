"""Check new CreateModel migrations against PRAHO's naming and comment convention."""

from __future__ import annotations

import argparse
import ast
import re

from scripts.migration_checksums import ROOT, file_hashes, repository_baseline

PREFIXES = {
    "customers": "customer",
    "users": "user",
    "domains": "domain",
    "orders": "order",
    "products": "product",
    "tickets": "ticket",
    "integrations": "integration",
    "notifications": "notification",
    "promotions": "promotion",
    "settings": "setting",
}
ROOT_ENTITIES = {"customers", "users", "domains", "orders", "products", "tickets"}


def option(mapping: ast.AST | None, key: str) -> object:
    if isinstance(mapping, ast.Dict):
        for name, value in zip(mapping.keys, mapping.values, strict=True):
            if isinstance(name, ast.Constant) and name.value == key and isinstance(value, ast.Constant):
                return value.value
    return None


def schema_issues(source: str, app_label: str) -> list[str]:
    issues = []
    prefix = PREFIXES.get(app_label, app_label)
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        if name != "CreateModel":
            continue
        arguments = {keyword.arg: keyword.value for keyword in node.keywords}
        options = arguments.get("options")
        if option(options, "proxy") is True:
            continue
        model = arguments.get("name")
        model_name = str(model.value) if isinstance(model, ast.Constant) else "new model"
        label = f"{model_name} at line {node.lineno}"
        table = option(options, "db_table")
        if not isinstance(table, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", table):
            issues.append(f"{label}: declare a literal lowercase Meta.db_table")
        elif not table.startswith(f"{prefix}_") and not (
            app_label in ROOT_ENTITIES and table == app_label and model_name.lower() == prefix
        ):
            issues.append(f"{label}: db_table must follow ADR-0023's {prefix}_ prefix or root-entity convention")
        comment = option(options, "db_table_comment")
        if not isinstance(comment, str) or not comment.strip():
            issues.append(f"{label}: add a useful literal Meta.db_table_comment")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="origin/master")
    args = parser.parse_args()
    previous = repository_baseline(args.base_ref)["files"]
    issues = []
    for path in sorted(file_hashes(ROOT).keys() - previous.keys()):
        issues.extend(f"{path}: {issue}" for issue in schema_issues((ROOT / path).read_text(), path.split("/")[3]))
    for issue in issues:
        print(issue)
    if not issues:
        print("New model table names and comments verified; existing tables preserved")
    return bool(issues)


if __name__ == "__main__":
    raise SystemExit(main())
