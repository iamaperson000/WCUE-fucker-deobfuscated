#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


I_OFFSET = 20314
EXPR_RE = re.compile(r"I\(([0-9+\-()]+)\)")


def eval_arith(expr: str) -> int:
    if not re.fullmatch(r"[0-9+\-() \t]+", expr):
        raise ValueError(f"unsafe arithmetic expression: {expr!r}")
    return int(eval(expr, {"__builtins__": {}}, {}))


def comment_label(entry: dict) -> str:
    preview = entry["stage2_preview"]
    if entry["stage2_printable_ratio"] >= 0.85:
        label = preview
    else:
        label = f"hex:{entry['stage2_hex'][:32]}"
    label = label.replace("]]", "]\\]")
    return f"H[{entry['index']}]={label}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Annotate obfuscated I(...) lookups.")
    parser.add_argument(
        "--input",
        default="/Users/kanishkv/Developer/wcue deobf/source.lua",
        help="Path to the obfuscated source file.",
    )
    parser.add_argument(
        "--pool",
        default="/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool_stage2.json",
        help="Decoded stage2 string pool JSON.",
    )
    parser.add_argument(
        "--out-dir",
        default="/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts",
        help="Output directory for annotations.",
    )
    args = parser.parse_args()

    src = Path(args.input).read_text(encoding="utf-8")
    pool_entries = json.loads(Path(args.pool).read_text(encoding="utf-8"))
    pool = {entry["index"]: entry for entry in pool_entries}
    usage_counter: Counter[int] = Counter()

    def replace_match(match: re.Match[str]) -> str:
        expr = match.group(1)
        resolved = eval_arith(expr) + I_OFFSET
        entry = pool.get(resolved)
        if entry is None:
            return match.group(0) + "--[[H[?]=missing]]"
        usage_counter[resolved] += 1
        return match.group(0) + f"--[[{comment_label(entry)}]]"

    annotated = EXPR_RE.sub(replace_match, src)

    used_entries = []
    for index, count in usage_counter.most_common():
        entry = dict(pool[index])
        entry["use_count"] = count
        used_entries.append(entry)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "source_i_annotated.lua").write_text(annotated, encoding="utf-8")
    (out_dir / "used_i_lookups.json").write_text(
        json.dumps(used_entries, indent=2),
        encoding="utf-8",
    )

    lines = [f"unique_i_lookups: {len(used_entries)}", ""]
    for entry in used_entries:
        lines.append(
            f"H[{entry['index']:04d}] "
            f"use_count={entry['use_count']} "
            f"printable={entry['stage2_printable_ratio']} "
            f"preview={entry['stage2_preview']}"
        )
    (out_dir / "used_i_lookups.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"annotated {sum(usage_counter.values())} I(...) lookups across {len(used_entries)} unique H entries")


if __name__ == "__main__":
    main()
