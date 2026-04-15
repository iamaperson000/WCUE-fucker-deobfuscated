#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import List


DEFAULT_INPUT = "/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/vm_wrappers/helper_21_a.lua"


def is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def read_identifier(src: str, pos: int) -> tuple[str, int]:
    start = pos
    while pos < len(src) and is_ident_char(src[pos]):
        pos += 1
    return src[start:pos], pos


def skip_string(src: str, pos: int) -> int:
    quote = src[pos]
    pos += 1
    while pos < len(src):
        ch = src[pos]
        if ch == "\\":
            pos += 2
            continue
        if ch == quote:
            return pos + 1
        pos += 1
    raise ValueError("unterminated string")


def skip_comment(src: str, pos: int) -> int:
    if src.startswith("--[[", pos):
        end = src.find("]]", pos + 4)
        if end == -1:
            raise ValueError("unterminated long comment")
        return end + 2
    if src.startswith("--", pos):
        end = src.find("\n", pos + 2)
        return len(src) if end == -1 else end + 1
    return pos


def skip_ws(src: str, pos: int) -> int:
    while pos < len(src) and src[pos].isspace():
        pos += 1
    return pos


def safe_eval_int(expr: str) -> int:
    if not re.fullmatch(r"[0-9+\-() ]+", expr):
        raise ValueError(f"non-arithmetic expression: {expr!r}")
    return int(eval(expr, {"__builtins__": None}, {}))


def line_number_for(line_starts: List[int], pos: int) -> int:
    return bisect_right(line_starts, pos)


@dataclass
class TextNode:
    start: int
    end: int


@dataclass
class IfNode:
    start: int
    condition: str
    threshold: int
    then_nodes: list
    else_nodes: list


Node = TextNode | IfNode


@dataclass
class Leaf:
    low: int
    high: int
    start: int
    code: str


@dataclass
class AssignmentCandidate:
    line: int
    code: str
    states: list[int]


@dataclass
class LeafRecord:
    leaf: Leaf
    start_line: int
    end_line: int
    candidates: list[AssignmentCandidate]


def find_next_control(src: str, pos: int) -> tuple[int, str] | None:
    while pos < len(src):
        if src.startswith("--", pos):
            pos = skip_comment(src, pos)
            continue
        ch = src[pos]
        if ch in ('"', "'"):
            pos = skip_string(src, pos)
            continue
        if is_ident_char(ch):
            word, end = read_identifier(src, pos)
            if word in {"if", "else", "end", "elseif"}:
                before_ok = pos == 0 or not is_ident_char(src[pos - 1])
                after_ok = end == len(src) or not is_ident_char(src[end])
                if before_ok and after_ok:
                    return pos, word
            pos = end
            continue
        pos += 1
    return None


def parse_condition(src: str, pos: int) -> tuple[str, int, int]:
    assert src.startswith("if", pos)
    pos += 2
    cond_start = pos
    paren_depth = 0
    brace_depth = 0
    bracket_depth = 0
    while pos < len(src):
        if src.startswith("--", pos):
            pos = skip_comment(src, pos)
            continue
        ch = src[pos]
        if ch in ('"', "'"):
            pos = skip_string(src, pos)
            continue
        if ch == "(":
            paren_depth += 1
            pos += 1
            continue
        if ch == ")":
            paren_depth -= 1
            pos += 1
            continue
        if ch == "{":
            brace_depth += 1
            pos += 1
            continue
        if ch == "}":
            brace_depth -= 1
            pos += 1
            continue
        if ch == "[":
            bracket_depth += 1
            pos += 1
            continue
        if ch == "]":
            bracket_depth -= 1
            pos += 1
            continue
        if (
            paren_depth == 0
            and brace_depth == 0
            and bracket_depth == 0
            and src.startswith("then", pos)
            and (pos == 0 or not is_ident_char(src[pos - 1]))
            and (pos + 4 == len(src) or not is_ident_char(src[pos + 4]))
        ):
            cond = src[cond_start:pos].strip()
            m = re.fullmatch(r"a<([0-9+\-() ]+)", cond.replace(" ", ""))
            if not m:
                raise ValueError(f"unsupported condition: {cond!r}")
            threshold = safe_eval_int(m.group(1))
            return cond, threshold, pos + 4
        pos += 1
    raise ValueError("unterminated if condition")


def parse_block(src: str, pos: int) -> tuple[list[Node], int, str]:
    nodes: list[Node] = []
    text_start = pos
    while pos < len(src):
        control = find_next_control(src, pos)
        if control is None:
            if text_start < len(src):
                nodes.append(TextNode(text_start, len(src)))
            return nodes, len(src), "eof"
        ctrl_pos, word = control
        if word in {"else", "end", "elseif"}:
            if text_start < ctrl_pos:
                nodes.append(TextNode(text_start, ctrl_pos))
            return nodes, ctrl_pos, word
        if text_start < ctrl_pos:
            nodes.append(TextNode(text_start, ctrl_pos))
        if_node, pos = parse_if(src, ctrl_pos)
        nodes.append(if_node)
        text_start = pos
    return nodes, pos, "eof"


def parse_if(src: str, pos: int) -> tuple[IfNode, int]:
    start = pos
    condition, threshold, pos = parse_condition(src, pos)
    pos = skip_ws(src, pos)
    then_nodes, pos, stop_word = parse_block(src, pos)
    if stop_word == "elseif":
        else_if, pos = parse_if(src, pos)
        else_nodes = [else_if]
    elif stop_word == "else":
        pos += 4
        pos = skip_ws(src, pos)
        else_nodes, pos, stop_word = parse_block(src, pos)
        if stop_word != "end":
            raise ValueError(f"expected end after else, got {stop_word!r}")
        pos += 3
    elif stop_word == "end":
        else_nodes = []
        pos += 3
    else:
        raise ValueError(f"expected else/end, got {stop_word!r}")
    return IfNode(start, condition, threshold, then_nodes, else_nodes), pos


def collect_leaves(nodes: list[Node], src: str) -> list[Leaf]:
    leaves: list[Leaf] = []

    def walk(queue: list[Node], low: int, high: int, chunks: list[tuple[int, int]], start_pos: int | None) -> None:
        if not queue:
            code = "".join(src[s:e] for s, e in chunks).strip()
            if code:
                leaves.append(Leaf(low, high, start_pos or 0, code))
            return
        node = queue[0]
        rest = queue[1:]
        if isinstance(node, TextNode):
            node_text = src[node.start:node.end]
            if node_text.strip():
                next_chunks = chunks + [(node.start, node.end)]
                next_start = start_pos if start_pos is not None else node.start
            else:
                next_chunks = chunks
                next_start = start_pos
            walk(rest, low, high, next_chunks, next_start)
            return
        walk(node.then_nodes + rest, low, min(high, node.threshold), chunks.copy(), start_pos)
        walk(node.else_nodes + rest, max(low, node.threshold), high, chunks.copy(), start_pos)

    walk(nodes, -math.inf, math.inf, [], None)
    return leaves


def extract_assignment_candidates(code: str, start_line: int) -> list[AssignmentCandidate]:
    candidates: list[AssignmentCandidate] = []
    for offset, raw_line in enumerate(code.splitlines(), start=0):
        states: list[int] = []
        for expr in re.findall(r"\ba\s*=\s*([0-9+\-() ]+)", raw_line):
            try:
                states.append(safe_eval_int(expr))
            except Exception:
                continue
        for left, right in re.findall(
            r"\ba\s*=\s*[^\\n]{0,200}?\band\s*([0-9+\-() ]+)\s*or\s*([0-9+\-() ]+)",
            raw_line,
        ):
            try:
                states.append(safe_eval_int(left))
            except Exception:
                pass
            try:
                states.append(safe_eval_int(right))
            except Exception:
                pass
        if states:
            candidates.append(AssignmentCandidate(start_line + offset, raw_line.strip(), sorted(set(states))))
    return candidates


def build_leaf_index(src: str) -> list[Leaf]:
    while_idx = src.find("while a do")
    if while_idx == -1:
        raise ValueError("could not find dispatcher loop")
    body_start = while_idx + len("while a do")
    body_start = skip_ws(src, body_start)
    nodes, _, _ = parse_block(src, body_start)
    return collect_leaves(nodes, src)


def find_leaf_for_state(leaves: list[Leaf], state: int) -> Leaf | None:
    for leaf in leaves:
        if leaf.low <= state < leaf.high:
            return leaf
    return None


def find_record_for_line(records: list[LeafRecord], line: int) -> LeafRecord | None:
    for record in records:
        if record.start_line <= line <= record.end_line:
            return record
    return None


def pretty_interval(leaf: Leaf) -> str:
    low = "-inf" if leaf.low == -math.inf else str(int(leaf.low))
    high = "inf" if leaf.high == math.inf else str(int(leaf.high))
    return f"[{low}, {high})"


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace dispatcher state intervals and predecessor jumps.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Formatted dispatcher helper file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--state", type=int, help="State value to resolve.")
    group.add_argument("--line", type=int, help="Line number to resolve.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--predecessor-depth", type=int, default=1, help="How many predecessor layers to search.")
    args = parser.parse_args()

    src_path = Path(args.input)
    src = src_path.read_text(encoding="utf-8")
    line_starts = [0]
    for idx, ch in enumerate(src):
        if ch == "\n":
            line_starts.append(idx + 1)

    leaves = build_leaf_index(src)
    records: list[LeafRecord] = []
    for leaf in leaves:
        start_line = line_number_for(line_starts, leaf.start)
        candidates = extract_assignment_candidates(leaf.code, start_line)
        end_line = start_line + max(0, len(leaf.code.splitlines()) - 1)
        records.append(LeafRecord(leaf=leaf, start_line=start_line, end_line=end_line, candidates=candidates))

    if args.state is not None:
        current = find_leaf_for_state(leaves, args.state)
        if current is None:
            raise SystemExit(f"state {args.state} not found")
        target_label = f"state {args.state}"
        seed_intervals = {(current.low, current.high)}
    else:
        record = find_record_for_line(records, args.line)
        if record is None:
            raise SystemExit(f"line {args.line} not found")
        current = record.leaf
        target_label = f"line {args.line}"
        seed_intervals = {(current.low, current.high)}

    predecessor_layers: list[list[AssignmentCandidate]] = []
    wanted_intervals = seed_intervals
    seen_intervals = set(wanted_intervals)
    for _ in range(max(0, args.predecessor_depth)):
        layer: list[AssignmentCandidate] = []
        next_intervals: set[tuple[int, int]] = set()
        for record in records:
            for candidate in record.candidates:
                if any(low <= state < high for low, high in wanted_intervals for state in candidate.states):
                    layer.append(candidate)
                    next_record = find_record_for_line(records, candidate.line)
                    if next_record is not None:
                        interval = (next_record.leaf.low, next_record.leaf.high)
                        if interval not in seen_intervals:
                            next_intervals.add(interval)
        if not layer:
            break
        predecessor_layers.append(layer)
        wanted_intervals = next_intervals
        seen_intervals.update(next_intervals)

    result = {
        "state": args.state,
        "line": args.line,
        "target": target_label,
        "interval": pretty_interval(current),
        "leaf_start_line": line_number_for(line_starts, current.start),
        "leaf_code": current.code,
        "predecessor_layers": [
            [
                {"line": item.line, "states": item.states, "code": item.code}
                for item in layer
            ]
            for layer in predecessor_layers
        ],
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"target: {target_label}")
    print(f"interval: {result['interval']}")
    print(f"leaf_start_line: {result['leaf_start_line']}")
    print("leaf_code:")
    print(result["leaf_code"])
    if predecessor_layers:
        print("predecessors:")
        for depth, layer in enumerate(predecessor_layers, start=1):
            print(f"  depth {depth}:")
            for item in layer[:40]:
                print(f"    line {item.line}: states={item.states} code={item.code}")


if __name__ == "__main__":
    main()
