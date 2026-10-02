#!/usr/bin/env python3
"""Object-level schema, state and seed-data comparator for two databases.

Built for the migration reset (ADR-0052): it proves that a database built
from the regenerated migrations is equivalent to one built from the old
chain. Text diffs of ``pg_dump`` output are useless for that, because column
order, generated names and statement order all change. This tool emits a
canonical JSON document per database and compares the documents key by key.

Subcommands::

    pg     --dsn DSN            dump a PostgreSQL database (pg_catalog)
    sqlite --path FILE          dump a SQLite database (sqlite_master + PRAGMAs)
    state                       dump Django's migration state (run inside a
                                configured Django project: DJANGO_SETTINGS_MODULE
                                and PYTHONPATH must point at the tree to load)
    diff   A.json B.json        compare two documents; exit 1 on any difference
           [--accept FILE]      JSON list of {"section", "key", "reason"};
                                exact keys only, never patterns

Coverage
  PostgreSQL: columns by name (type, nullability, default, collation,
  identity, generated; physical order ignored), constraints by
  ``pg_get_constraintdef``, indexes by ``pg_get_indexdef`` with the index
  name masked, functions by ``pg_get_functiondef``, triggers by
  ``pg_get_triggerdef``, sequence ownership and parameters, table and column
  comments, extensions and user-defined types.
  SQLite: each column's definition text parsed out of ``CREATE TABLE`` plus
  ``PRAGMA table_xinfo``, table-level constraints, CHECK constraints by name,
  ``PRAGMA foreign_key_list``, indexes (masked SQL, or the ``index_xinfo``
  shape for automatic indexes) and triggers.
  Both backends: row counts for every table except ``django_migrations``,
  and contents by natural key for every table with rows (generated ``id`` and
  timestamp columns excluded). Django-Q schedules compare by name, func,
  schedule_type, minutes and repeats; queued tasks by count only.
  Names (constraints, indexes, sequences) are a separate pass; ``diff`` pairs
  an old-only name with a new-only name when they share a definition.
  State: every model's fields (``deconstruct()`` as the migration writer
  serializes it), options, constraints and indexes by name, bases, managers.

Stated limits: sequence values (including SQLite's ``sqlite_sequence``),
privileges and ownership are not compared.
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import json
import re
import sqlite3
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = "public"
EXCLUDED_ROW_TABLES = frozenset({"django_migrations", "sqlite_sequence"})
COUNT_ONLY_TABLES = frozenset({"django_q_ormq", "django_q_task"})
GENERIC_EXCLUDED_COLUMNS = frozenset({"id", "created_at", "updated_at"})
TIMESTAMP_TYPES = ("timestamp", "datetime")

# Natural-key queries. Each works unchanged on PostgreSQL and SQLite.
DATA_RULES: dict[str, str] = {
    "django_content_type": 'SELECT "app_label", "model" FROM "django_content_type"',
    "auth_permission": (
        'SELECT ct."app_label", ct."model", p."codename", p."name" FROM "auth_permission" p '
        'JOIN "django_content_type" ct ON ct."id" = p."content_type_id"'
    ),
    "django_q_schedule": ('SELECT "name", "func", "schedule_type", "minutes", "repeats" FROM "django_q_schedule"'),
}

Document = dict[str, Any]
Sections = dict[str, dict[str, Any]]


# --------------------------------------------------------------------------- helpers


def _canon(value: Any) -> Any:
    """Convert a driver value into a JSON-stable form."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(value, (dt.datetime, dt.date, dt.time, decimal.Decimal, uuid.UUID, memoryview, bytes)):
        return str(bytes(value).hex() if isinstance(value, (memoryview, bytes)) else value)
    return value


def _add(section: dict[str, Any], key: str) -> None:
    section[key] = section.get(key, 0) + 1


def _row_key(table: str, columns: list[str], row: tuple[Any, ...]) -> str:
    payload = {col: _canon(val) for col, val in zip(columns, row, strict=True)}
    return f"{table} | {json.dumps(payload, sort_keys=True, ensure_ascii=False)}"


def _mask_index_name(indexdef: str) -> str:
    return re.sub(r"^(CREATE (?:UNIQUE )?INDEX )(?:IF NOT EXISTS )?(\S+)( ON )", r"\1<name>\3", indexdef)


def _data_sections(cursor: Any, tables: list[str], column_types: dict[str, dict[str, str]], sections: Sections) -> None:
    rowcounts = sections.setdefault("rowcounts", {})
    data = sections.setdefault("data", {})
    rules = sections.setdefault("data_rules", {})
    for table in tables:
        if table in EXCLUDED_ROW_TABLES:
            continue
        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')  # noqa: S608 -- catalog identifiers
        count = int(cursor.fetchone()[0])
        rowcounts[table] = count
        if count == 0:
            continue
        if table in COUNT_ONLY_TABLES:
            rules[table] = "count-only"
            continue
        if table in DATA_RULES:
            rules[table] = "natural-key"
            query = DATA_RULES[table]
        else:
            rules[table] = "generic"
            keep = [
                col
                for col, col_type in sorted(column_types[table].items())
                if col not in GENERIC_EXCLUDED_COLUMNS and not col_type.lower().startswith(TIMESTAMP_TYPES)
            ]
            query = "SELECT " + ", ".join(f'"{c}"' for c in keep) + f' FROM "{table}"'  # noqa: S608
        cursor.execute(query)
        columns = [d[0] for d in cursor.description]
        for row in cursor.fetchall():
            _add(data, _row_key(table, columns, tuple(row)))


# --------------------------------------------------------------------------- PostgreSQL


def dump_pg(dsn: str) -> Document:
    import psycopg

    sections: Sections = defaultdict(dict)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relkind IN ('r','p','v','m','f')",
            [SCHEMA],
        )
        relations: dict[str, str] = dict(cur.fetchall())
        sections["tables"] = dict(relations)

        cur.execute(
            """
            SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
                   pg_get_expr(d.adbin, d.adrelid), coll.collname, a.attidentity, a.attgenerated
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
            LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
            WHERE n.nspname = %s AND c.relkind IN ('r','p','v','m','f') AND a.attnum > 0 AND NOT a.attisdropped
            """,
            [SCHEMA],
        )
        column_types: dict[str, dict[str, str]] = defaultdict(dict)
        for table, col, col_type, notnull, default, collation, identity, generated in cur.fetchall():
            column_types[table][col] = col_type
            sections["columns"][f"{table}.{col}"] = {
                "type": col_type,
                "notnull": notnull,
                "default": default,
                "collation": collation,
                "identity": identity,
                "generated": generated,
            }

        cur.execute(
            """
            SELECT c.relname, con.conname, con.contype, pg_get_constraintdef(con.oid, true)
            FROM pg_constraint con
            JOIN pg_class c ON c.oid = con.conrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s
            """,
            [SCHEMA],
        )
        for table, name, contype, definition in cur.fetchall():
            _add(sections["constraints"], f"{table} | {contype} | {definition}")
            sections["names.constraints"][f"{table}.{name}"] = f"{table} | {contype} | {definition}"

        cur.execute(
            """
            SELECT c.relname, i.relname, pg_get_indexdef(i.oid)
            FROM pg_index x
            JOIN pg_class i ON i.oid = x.indexrelid
            JOIN pg_class c ON c.oid = x.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s
            """,
            [SCHEMA],
        )
        for table, name, indexdef in cur.fetchall():
            masked = f"{table} | {_mask_index_name(indexdef)}"
            _add(sections["indexes"], masked)
            sections["names.indexes"][f"{table}.{name}"] = masked

        cur.execute(
            """
            SELECT p.proname, pg_get_function_identity_arguments(p.oid), pg_get_functiondef(p.oid)
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = %s AND p.prokind IN ('f','p')
              AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
            """,
            [SCHEMA],
        )
        for name, args, definition in cur.fetchall():
            sections["functions"][f"{name}({args})"] = definition

        cur.execute(
            """
            SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid, true)
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND NOT t.tgisinternal
            """,
            [SCHEMA],
        )
        for table, name, definition in cur.fetchall():
            sections["triggers"][f"{table}.{name}"] = definition

        cur.execute(
            """
            SELECT s.relname, dc.relname, a.attname, d.deptype,
                   ps.data_type::text, ps.start_value, ps.increment_by, ps.min_value, ps.max_value, ps.cycle
            FROM pg_class s
            JOIN pg_namespace n ON n.oid = s.relnamespace
            JOIN pg_sequences ps ON ps.schemaname = n.nspname AND ps.sequencename = s.relname
            LEFT JOIN pg_depend d ON d.objid = s.oid AND d.classid = 'pg_class'::regclass
                 AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a','i')
            LEFT JOIN pg_class dc ON dc.oid = d.refobjid
            LEFT JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
            WHERE s.relkind = 'S' AND n.nspname = %s
            """,
            [SCHEMA],
        )
        for seq, owner_table, owner_col, deptype, *params in cur.fetchall():
            owner = f"{owner_table}.{owner_col}" if owner_table else f"<unowned:{seq}>"
            sections["sequences"][owner] = {
                "deptype": deptype,
                "params": [str(p) for p in params],
            }
            sections["names.sequences"][seq] = owner

        cur.execute(
            """
            SELECT c.relname, a.attname, d.description
            FROM pg_description d
            JOIN pg_class c ON c.oid = d.objoid AND d.classoid = 'pg_class'::regclass
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.objsubid AND d.objsubid > 0
            WHERE n.nspname = %s
            """,
            [SCHEMA],
        )
        for table, col, description in cur.fetchall():
            sections["comments"][f"{table}.{col}" if col else table] = description

        cur.execute("SELECT extname, extversion FROM pg_extension")
        sections["extensions"] = dict(cur.fetchall())

        cur.execute(
            "SELECT t.typname, t.typtype FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
            "WHERE n.nspname = %s AND t.typtype IN ('e','d','r','m')",
            [SCHEMA],
        )
        sections["types"] = dict(cur.fetchall())

        tables = sorted(name for name, kind in relations.items() if kind in ("r", "p"))
        _data_sections(cur, tables, column_types, sections)

    return {"kind": "postgresql", "source": _redact_dsn(dsn), "sections": dict(sections)}


def _redact_dsn(dsn: str) -> str:
    return re.sub(r"password=\S+", "password=***", re.sub(r"://([^:@/]+):[^@]+@", r"://\1:***@", dsn))


# --------------------------------------------------------------------------- SQLite


def _split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on commas outside parentheses and quotes."""
    items: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for char in body:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"', "`"):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if "".join(current).strip():
        items.append("".join(current).strip())
    return items


_TABLE_CONSTRAINT_PREFIXES = ("CONSTRAINT", "UNIQUE", "PRIMARY", "FOREIGN", "CHECK")


def _parse_create_table(sql: str) -> tuple[dict[str, str], list[str]]:
    """Return ({column: definition}, [table-level constraint clauses])."""
    body = sql[sql.index("(") + 1 : sql.rindex(")")]
    columns: dict[str, str] = {}
    constraints: list[str] = []
    for item in _split_top_level(body):
        if item.upper().startswith(_TABLE_CONSTRAINT_PREFIXES):
            constraints.append(item)
            continue
        match = re.match(r'^(?:"([^"]+)"|`([^`]+)`|(\w+))\s*(.*)$', item, re.DOTALL)
        if not match:
            raise ValueError(f"unparseable column definition: {item!r}")
        name = match.group(1) or match.group(2) or match.group(3)
        columns[name] = " ".join(match.group(4).split())
    return columns, constraints


def dump_sqlite(path: str) -> Document:
    sections: Sections = defaultdict(dict)
    conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        master = cur.fetchall()
        tables = sorted(name for kind, name, _t, _s in master if kind == "table" and not name.startswith("sqlite_"))
        column_types: dict[str, dict[str, str]] = defaultdict(dict)
        for kind, name, table, sql in master:
            if kind == "table" and name.startswith("sqlite_"):
                continue
            if kind == "table":
                sections["tables"][name] = "table"
                coldefs, table_constraints = _parse_create_table(sql)
                for _cid, col, col_type, notnull, default, pk, hidden in cur.execute(
                    f'PRAGMA table_xinfo("{name}")'
                ).fetchall():
                    column_types[name][col] = col_type
                    sections["columns"][f"{name}.{col}"] = {
                        "definition": coldefs.get(col),
                        "type": col_type,
                        "notnull": notnull,
                        "default": default,
                        "pk": pk,
                        "hidden": hidden,
                    }
                for clause in table_constraints:
                    normalized = " ".join(clause.split())
                    named = re.match(r'^CONSTRAINT\s+"?([^"\s]+)"?\s+(.*)$', normalized, re.IGNORECASE | re.DOTALL)
                    if named and named.group(2).upper().startswith("CHECK"):
                        sections["check_constraints"][f"{name} | {named.group(1)}"] = named.group(2)
                        continue
                    body = named.group(2) if named else normalized
                    _add(sections["table_constraints"], f"{name} | {body}")
                    if named:
                        sections["names.table_constraints"][f"{name}.{named.group(1)}"] = f"{name} | {body}"
                for fk in cur.execute(f'PRAGMA foreign_key_list("{name}")').fetchall():
                    _id, _seq, ref_table, from_col, to_col, on_update, on_delete, match_ = fk
                    _add(
                        sections["foreign_keys"],
                        f"{name}.{from_col} -> {ref_table}.{to_col} | update={on_update} "
                        f"delete={on_delete} match={match_}",
                    )
            elif kind == "index":
                if sql:
                    masked = f"{table} | {' '.join(_mask_index_name(sql).split())}"
                else:
                    flags = next(row for row in cur.execute(f'PRAGMA index_list("{table}")') if row[1] == name)
                    cols = [
                        f"{row[2]}{' DESC' if row[3] else ''}"
                        for row in cur.execute(f'PRAGMA index_xinfo("{name}")').fetchall()
                        if row[5]
                    ]
                    masked = (
                        f"{table} | AUTO unique={flags[2]} origin={flags[3]} partial={flags[4]} ({', '.join(cols)})"
                    )
                _add(sections["indexes"], masked)
                sections["names.indexes"][f"{table}.{name}"] = masked
            elif kind == "trigger":
                sections["triggers"][f"{table}.{name}"] = " ".join(sql.split())
            elif kind == "view":
                sections["views"][name] = " ".join(sql.split())
        _data_sections(cur, tables, column_types, sections)
    finally:
        conn.close()
    return {"kind": "sqlite", "source": str(Path(path).resolve()), "sections": dict(sections)}


# --------------------------------------------------------------------------- Django state


def dump_state() -> Document:
    import django

    django.setup()
    from django.apps import apps as django_apps
    from django.db.migrations.loader import MigrationLoader
    from django.db.migrations.writer import MigrationWriter
    from django.utils import translation

    translation.deactivate_all()

    def ser(value: Any) -> str:
        return MigrationWriter.serialize(value)[0]

    loader = MigrationLoader(None, ignore_no_migrations=True)
    sections: Sections = defaultdict(dict)
    for app_config in django_apps.get_app_configs():
        module_name, _explicit = MigrationLoader.migrations_module(app_config.label)
        module = sys.modules.get(module_name or "")
        sections["migration_modules"][app_config.label] = getattr(module, "__file__", None)
    sections["graph"]["leaf_count"] = len(loader.graph.leaf_nodes())
    sections["graph"]["node_count"] = len(loader.graph.nodes)

    state = loader.project_state()
    for (app_label, model_name), model_state in sorted(state.models.items()):
        prefix = f"{app_label}.{model_name}"
        for field_name, field in model_state.fields.items():
            sections["fields"][f"{prefix}.{field_name}"] = ser(field)
        for option, value in model_state.options.items():
            if option in ("constraints", "indexes"):
                for item in value:
                    sections[option][f"{prefix}.{item.name}"] = ser(item)
            else:
                sections["options"][f"{prefix}.{option}"] = ser(value)
        sections["bases"][prefix] = ser(model_state.bases)
        sections["managers"][prefix] = ser([(name, manager) for name, manager in model_state.managers])
    graph = sections.pop("graph")
    modules = sections.pop("migration_modules")
    return {"kind": "state", "header": {"graph": graph, "migration_modules": modules}, "sections": dict(sections)}


# --------------------------------------------------------------------------- diff


def _load(path: str) -> Document:
    document: Document = json.loads(Path(path).read_text(encoding="utf-8"))
    return document


def _name_pairs(a_names: dict[str, Any], b_names: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Pair old-only and new-only names that share a definition."""
    only_a = {k: v for k, v in a_names.items() if k not in b_names}
    only_b = {k: v for k, v in b_names.items() if k not in a_names}
    by_def_b: dict[str, list[str]] = defaultdict(list)
    for key, definition in sorted(only_b.items()):
        by_def_b[json.dumps(definition, sort_keys=True)].append(key)
    paired: list[str] = []
    unpaired_a: list[str] = []
    for key, definition in sorted(only_a.items()):
        candidates = by_def_b.get(json.dumps(definition, sort_keys=True))
        if candidates:
            paired.append(f"{key} -> {candidates.pop(0)}  (same definition: {definition})")
        else:
            unpaired_a.append(f"{key}  ({definition})")
    unpaired_b = [f"{k}  ({only_b[k]})" for defs in by_def_b.values() for k in defs]
    changed = [
        f"{k}: {a_names[k]!r} -> {b_names[k]!r}"
        for k in sorted(set(a_names) & set(b_names))
        if a_names[k] != b_names[k]
    ]
    return paired, unpaired_a, sorted(unpaired_b) + changed


def diff_documents(a: Document, b: Document, accepted: dict[tuple[str, str], str]) -> int:
    if a.get("kind") != b.get("kind"):
        print(f"cannot compare a {a.get('kind')} document with a {b.get('kind')} document")
        return 2
    a_sections, b_sections = a["sections"], b["sections"]
    failures = 0
    used: set[tuple[str, str]] = set()

    for section in sorted(set(a_sections) | set(b_sections)):
        if section.startswith("names."):
            continue
        a_items, b_items = a_sections.get(section, {}), b_sections.get(section, {})
        lines: list[str] = []
        for key in sorted(set(a_items) | set(b_items)):
            if key in a_items and key in b_items and a_items[key] == b_items[key]:
                continue
            if key not in b_items:
                change = f"only in A: {key} = {json.dumps(a_items[key], ensure_ascii=False)}"
            elif key not in a_items:
                change = f"only in B: {key} = {json.dumps(b_items[key], ensure_ascii=False)}"
            else:
                change = (
                    f"changed:   {key}\n      A = {json.dumps(a_items[key], ensure_ascii=False)}"
                    f"\n      B = {json.dumps(b_items[key], ensure_ascii=False)}"
                )
            if (section, key) in accepted:
                used.add((section, key))
                lines.append(f"  ACCEPTED ({accepted[(section, key)]}) {change}")
            else:
                failures += 1
                lines.append(f"  {change}")
        if lines:
            print(f"[{section}]")
            print("\n".join(lines))

    name_sections = sorted(s for s in set(a_sections) | set(b_sections) if s.startswith("names."))
    name_failures = 0
    for section in name_sections:
        paired, unpaired_a, unpaired_b = _name_pairs(a_sections.get(section, {}), b_sections.get(section, {}))
        if not (paired or unpaired_a or unpaired_b):
            continue
        print(f"[{section}] (names pass)")
        for line in paired:
            print(f"  renamed (generation artifact): {line}")
        for line in unpaired_a:
            name_failures += 1
            print(f"  UNPAIRED only in A: {line}")
        for line in unpaired_b:
            name_failures += 1
            print(f"  UNPAIRED only in B / changed: {line}")

    for key in sorted(set(accepted) - used):
        print(f"note: accepted difference not seen: {key[0]} | {key[1]}")
    print(f"summary: {failures} definition difference(s), {name_failures} unpaired name(s)")
    return 1 if failures or name_failures else 0


# --------------------------------------------------------------------------- CLI


def _write(document: Document, out: str | None) -> None:
    text = json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False, default=str) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    pg = sub.add_parser("pg")
    pg.add_argument("--dsn", required=True)
    pg.add_argument("-o", "--out")
    lite = sub.add_parser("sqlite")
    lite.add_argument("--path", required=True)
    lite.add_argument("-o", "--out")
    state = sub.add_parser("state")
    state.add_argument("-o", "--out")
    diff = sub.add_parser("diff")
    diff.add_argument("a")
    diff.add_argument("b")
    diff.add_argument("--accept")
    args = parser.parse_args(argv)

    if args.command == "pg":
        _write(dump_pg(args.dsn), args.out)
    elif args.command == "sqlite":
        if not Path(args.path).is_file():
            parser.error(f"no such SQLite file: {args.path}")
        _write(dump_sqlite(args.path), args.out)
    elif args.command == "state":
        _write(dump_state(), args.out)
    else:
        accepted: dict[tuple[str, str], str] = {}
        if args.accept:
            for entry in json.loads(Path(args.accept).read_text(encoding="utf-8")):
                accepted[(entry["section"], entry["key"])] = entry["reason"]
        return diff_documents(_load(args.a), _load(args.b), accepted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
