#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path("/Users/kanishkv/Developer/wcue deobf/wcue-decompile")
HELPER_PATH = ROOT / "artifacts" / "vm_wrappers" / "helper_21_a.lua"
OUT_DIR = ROOT / "artifacts" / "branch_traces"

TARGET_LINES = {
    4001: "loader_small",
    5796: "loader_bootstrap",
}

I_COMMENT_RE = re.compile(r"I\([^)]*\)--\[\[H\[(\d+)\]=([^\]]*)\]\]")
CALL_RE = re.compile(r"([A-Za-z][A-Za-z0-9]*)\((.*)\)")
INDEX_RE = re.compile(r"([A-Za-z][A-Za-z0-9]*)\[([A-Za-z][A-Za-z0-9]*)\]")
W_SLOT_RE = re.compile(r"W\[([A-Za-z][A-Za-z0-9]*)\]")
H_SLOT_RE = re.compile(r"H\[([A-Za-z][A-Za-z0-9]*)\]")
SIMPLE_VAR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def stringify_i_value(index: int, value: str) -> str:
    if value.startswith("hex:"):
        return f"H[{index}]"
    return json.dumps(value)


def split_args(arg_text: str) -> list[str]:
    if not arg_text:
        return []
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in arg_text:
        if ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)
        if ch in "({[":
            depth += 1
        elif ch in ")}]" and depth > 0:
            depth -= 1
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def parse_assignments(line: str) -> list[tuple[str, str]]:
    """Parse one long dispatcher line without regex backtracking."""
    assignments: list[tuple[str, str]] = []
    length = len(line)
    index = 0

    while index < length:
        while index < length and line[index].isspace():
            index += 1

        if index >= length or not line[index].isalpha():
            index += 1
            continue

        name_start = index
        while index < length and line[index].isalnum():
            index += 1

        if index >= length or line[index] != "=":
            continue

        name = line[name_start:index]
        index += 1
        expr_start = index
        depth = 0

        while index < length:
            if line.startswith("--[[", index):
                comment_end = line.find("]]", index + 4)
                if comment_end == -1:
                    index = length
                    break
                index = comment_end + 2
                continue

            ch = line[index]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)

            boundary = False
            next_start: int | None = None
            if depth == 0:
                if ch.isspace():
                    probe = index
                    while probe < length and line[probe].isspace():
                        probe += 1
                    end = probe
                    while end < length and line[end].isalnum():
                        end += 1
                    if end > probe and end < length and line[end] == "=":
                        boundary = True
                        next_start = probe
                elif ch.isalpha() and index > expr_start:
                    end = index
                    while end < length and line[end].isalnum():
                        end += 1
                    if (
                        end < length
                        and line[end] == "="
                        and line[index - 1] not in "([{,;:+-*/%^<>=~"
                    ):
                        boundary = True
                        next_start = index

            if boundary:
                assignments.append((name, line[expr_start:index]))
                index = next_start if next_start is not None else index
                break

            index += 1
        else:
            assignments.append((name, line[expr_start:]))
            break

    return assignments


def maybe_render_string(sym: str) -> str:
    if sym.startswith('"') and sym.endswith('"'):
        return sym
    return sym


def render_expr(expr: str, symbols: dict[str, str]) -> str:
    expr = expr.strip()

    match = I_COMMENT_RE.fullmatch(expr)
    if match:
        return stringify_i_value(int(match.group(1)), match.group(2))

    if expr in {"true", "false", "nil"}:
        return expr

    if SIMPLE_VAR_RE.fullmatch(expr):
        return symbols.get(expr, expr)

    match = H_SLOT_RE.fullmatch(expr)
    if match:
        inner = symbols.get(match.group(1), match.group(1))
        if inner.startswith('"') and inner.endswith('"'):
            return inner
        return f"H[{inner}]"

    match = W_SLOT_RE.fullmatch(expr)
    if match:
        inner = symbols.get(match.group(1), match.group(1))
        return f"W[{inner}]"

    match = INDEX_RE.fullmatch(expr)
    if match:
        table_name = symbols.get(match.group(1), match.group(1))
        key_name = symbols.get(match.group(2), match.group(2))
        return f"{table_name}[{key_name}]"

    match = CALL_RE.fullmatch(expr)
    if match:
        fn_name = symbols.get(match.group(1), match.group(1))
        args = [render_expr(part, symbols) for part in split_args(match.group(2))]
        return f"{fn_name}({', '.join(args)})"

    if ".." in expr:
        parts = [render_expr(part, symbols) for part in expr.split("..")]
        return " .. ".join(parts)

    rendered = expr
    for name, value in sorted(symbols.items(), key=lambda item: -len(item[0])):
        rendered = re.sub(rf"\b{name}\b", value, rendered)
    return rendered


def analyze_assignments(assignments: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    symbols: dict[str, str] = {}
    pretty_lines: list[str] = []
    trace_lines: list[str] = []

    for idx, (name, expr) in enumerate(assignments, start=1):
        expr = expr.strip()
        rendered = render_expr(expr, symbols)
        symbols[name] = rendered
        pretty_lines.append(f"{idx:03d}: {name} = {expr}")

        if expr.startswith("I("):
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if rendered.startswith("W[") and rendered.endswith("]"):
            trace_lines.append(f"{name} <- slot {rendered}")
            continue

        if "GetService" in rendered:
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if "HttpGet" in rendered:
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if "loadstring" in rendered:
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if "getgenv" in rendered:
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if ".." in expr and ("W[" in rendered or '"' in rendered):
            trace_lines.append(f"{name} <- {rendered}")
            continue

        if "W[" in rendered and ("H[" in rendered or '"' in rendered):
            trace_lines.append(f"{name} <- {rendered}")

    return pretty_lines, trace_lines


def extract_lookup_summary(assignments: list[tuple[str, str]]) -> list[str]:
    raw_symbols: dict[str, str] = {}
    output: list[str] = []

    for idx, (name, expr) in enumerate(assignments, start=1):
        raw_symbols[name] = expr.strip()
        expr = expr.strip()

        match = W_SLOT_RE.fullmatch(expr)
        if match and match.group(1) in {"b", "J"}:
            output.append(f"{idx:03d}: {name} <- {expr}")
            continue

        match = CALL_RE.fullmatch(expr)
        if match:
            fn_name, args = match.groups()
            raw_fn = raw_symbols.get(fn_name, fn_name)
            if raw_fn == "W[J]":
                rendered_args = [render_expr(part, {}) for part in split_args(args)]
                output.append(
                    f"{idx:03d}: {name} <- DECODE({', '.join(rendered_args)})"
                )
                continue

        match = INDEX_RE.fullmatch(expr)
        if match:
            table_name, key_name = match.groups()
            raw_table = raw_symbols.get(table_name, table_name)
            raw_key = raw_symbols.get(key_name, key_name)
            if raw_table == "W[b]":
                output.append(f"{idx:03d}: {name} <- LOOKUP({raw_key})")
                continue

    return output


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = HELPER_PATH.read_text().splitlines()
    manifest: dict[str, dict[str, str | int]] = {}

    for line_no, label in TARGET_LINES.items():
        raw_line = lines[line_no - 1].strip()
        assignments = parse_assignments(raw_line)
        pretty_lines, trace_lines = analyze_assignments(assignments)
        lookup_lines = extract_lookup_summary(assignments)

        pretty_path = OUT_DIR / f"{label}_pretty.lua"
        trace_path = OUT_DIR / f"{label}_trace.txt"
        lookup_path = OUT_DIR / f"{label}_lookups.txt"

        pretty_path.write_text("\n".join(pretty_lines) + "\n")
        trace_path.write_text("\n".join(trace_lines) + "\n")
        lookup_path.write_text("\n".join(lookup_lines) + "\n")

        manifest[label] = {
            "line": line_no,
            "pretty_path": str(pretty_path),
            "trace_path": str(trace_path),
            "lookup_path": str(lookup_path),
            "assignment_count": len(assignments),
        }

    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
