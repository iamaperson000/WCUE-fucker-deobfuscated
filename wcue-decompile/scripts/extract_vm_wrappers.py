#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


OUTER_HEADER = "return(function(H,X,l,v,S,K,B,R,u,A,O,q,J,P,L,z,j,b,a,Y,W,U,i,V,T,Z,g,f)"


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


def split_lhs_vars(src: str, start: int) -> tuple[list[str], int]:
    vars_: list[str] = []
    pos = start
    while pos < len(src):
        if src[pos].isspace():
            pos += 1
            continue
        if src[pos] == "=":
            return vars_, pos
        ident, pos = read_identifier(src, pos)
        if not ident:
            raise ValueError(f"expected identifier in LHS at offset {pos}")
        vars_.append(ident)
        while pos < len(src) and src[pos].isspace():
            pos += 1
        if pos < len(src) and src[pos] == ",":
            pos += 1
    raise ValueError("unterminated LHS variable list")


def split_top_level_expressions(src: str, start: int, count: int) -> tuple[list[str], int]:
    exprs: list[str] = []
    pos = start
    expr_start = start
    paren_depth = 0
    brace_depth = 0
    bracket_depth = 0
    block_depth = 0

    while pos < len(src):
        ch = src[pos]
        if src.startswith("--", pos):
            pos = skip_comment(src, pos)
            continue
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
        if is_ident_char(ch):
            word, new_pos = read_identifier(src, pos)
            if word in {"function", "then", "do", "repeat"}:
                block_depth += 1
            elif word in {"end", "until"}:
                block_depth -= 1
            pos = new_pos
            continue
        if (
            ch == ","
            and paren_depth == 0
            and brace_depth == 0
            and bracket_depth == 0
            and block_depth == 0
        ):
            exprs.append(src[expr_start:pos].strip())
            pos += 1
            expr_start = pos
            if len(exprs) == count - 1:
                break
            continue
        pos += 1

    if len(exprs) != count - 1:
        raise ValueError(f"expected to split {count - 1} expressions, found {len(exprs)}")

    final_marker = src.find("return(T(", expr_start)
    if final_marker == -1:
        raise ValueError("could not find outer return marker after wrapper assignment")
    exprs.append(src[expr_start:final_marker].strip())
    return exprs, final_marker


def infer_kind(expr: str) -> dict:
    stripped = expr.strip()
    if stripped.startswith("function("):
        sig_end = stripped.find(")")
        return {"kind": "function", "signature": stripped[: sig_end + 1]}
    if stripped == "{}":
        return {"kind": "table", "signature": "{}"}
    if re.fullmatch(r"[0-9+\-() ]+", stripped):
        return {"kind": "number", "signature": stripped}
    return {"kind": "expression", "signature": stripped[:80]}


def simple_format_lua(expr: str) -> str:
    out = expr
    replacements = [
        (" then ", " then\n"),
        (" do ", " do\n"),
        (" else ", "\nelse\n"),
        (" elseif ", "\nelseif "),
        (" while ", "\nwhile "),
        (" for ", "\nfor "),
        (" return ", "\nreturn "),
        (" local ", "\nlocal "),
        (",function(", ",\nfunction("),
        ("}function(", "}\nfunction("),
        (" end,", "\nend,\n"),
        (" end ", "\nend\n"),
    ]
    for old, new in replacements:
        out = out.replace(old, new)
    return out + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract the VM wrapper assignment from annotated source.")
    parser.add_argument(
        "--input",
        default="/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/source_i_annotated.lua",
        help="Annotated source file.",
    )
    parser.add_argument(
        "--out-dir",
        default="/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/vm_wrappers",
        help="Directory for extracted wrappers.",
    )
    args = parser.parse_args()

    src = Path(args.input).read_text(encoding="utf-8")
    start = src.find(OUTER_HEADER)
    if start == -1:
        raise ValueError("could not find outer wrapper header")

    body_start = start + len(OUTER_HEADER)
    lhs_vars, eq_pos = split_lhs_vars(src, body_start)
    rhs_exprs, _ = split_top_level_expressions(src, eq_pos + 1, len(lhs_vars))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    for index, (lhs, expr) in enumerate(zip(lhs_vars, rhs_exprs), start=1):
        meta = infer_kind(expr)
        helper_name = f"helper_{index:02d}_{lhs}.lua"
        (out_dir / helper_name).write_text(simple_format_lua(expr), encoding="utf-8")
        summary.append(
            {
                "index": index,
                "lhs": lhs,
                "kind": meta["kind"],
                "signature": meta["signature"],
                "length": len(expr),
                "file": helper_name,
            }
        )

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = []
    for item in summary:
        lines.append(
            f"{item['index']:02d} {item['lhs']}: kind={item['kind']} len={item['length']} sig={item['signature']} file={item['file']}"
        )
    (out_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"extracted {len(summary)} wrapper expressions to {out_dir}")


if __name__ == "__main__":
    main()
