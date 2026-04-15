#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path


BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def decode_lua_string_body(body: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.extend(ch.encode("latin-1"))
            i += 1
            continue

        i += 1
        if i >= len(body):
            out.append(ord("\\"))
            break

        esc = body[i]
        if esc.isdigit():
            digits = esc
            i += 1
            for _ in range(2):
                if i < len(body) and body[i].isdigit():
                    digits += body[i]
                    i += 1
                else:
                    break
            out.append(int(digits) & 0xFF)
            continue

        mapping = {
            "a": 0x07,
            "b": 0x08,
            "f": 0x0C,
            "n": 0x0A,
            "r": 0x0D,
            "t": 0x09,
            "v": 0x0B,
            "\\": 0x5C,
            '"': 0x22,
            "'": 0x27,
        }
        out.append(mapping.get(esc, ord(esc)))
        i += 1

    return bytes(out)


def find_string_pool(src: str) -> list[str]:
    marker = "local H={"
    start = src.find(marker)
    if start == -1:
        raise ValueError("could not find string pool marker")

    i = start + len(marker)
    entries: list[str] = []

    while i < len(src):
        ch = src[i]
        if ch in ",; \t\r\n":
            i += 1
            continue
        if ch == "}":
            break
        if ch != '"':
            raise ValueError(f"unexpected character in string pool at offset {i}: {ch!r}")

        i += 1
        buf: list[str] = []
        while i < len(src):
            ch = src[i]
            if ch == "\\":
                if i + 1 >= len(src):
                    raise ValueError("unterminated escape in string pool")
                j = i + 1
                if src[j].isdigit():
                    while j < len(src) and j < i + 4 and src[j].isdigit():
                        j += 1
                else:
                    j += 1
                buf.append(src[i:j])
                i = j
                continue
            if ch == '"':
                i += 1
                entries.append("".join(buf))
                break
            buf.append(ch)
            i += 1
        else:
            raise ValueError("unterminated string in string pool")

    return entries


def extract_braced(src: str, start: int) -> tuple[str, int]:
    if src[start] != "{":
        raise ValueError(f"expected '{{' at offset {start}")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(src)):
        ch = src[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            if depth == 0:
                return src[start + 1 : i], i
    raise ValueError(f"unterminated braced block at offset {start}")


def eval_arith(expr: str) -> int:
    expr = expr.strip()
    if not re.fullmatch(r"[0-9+\-() \t]+", expr):
        raise ValueError(f"unsafe arithmetic expression: {expr!r}")
    return int(eval(expr, {"__builtins__": {}}, {}))


def parse_swap_ranges(src: str, table_end: int) -> list[tuple[int, int]]:
    marker = "for I,a in ipairs("
    start = src.find(marker, table_end)
    if start == -1:
        raise ValueError("could not find swap-range block")
    brace_start = src.find("{", start)
    body, _ = extract_braced(src, brace_start)
    ranges = []
    for match in re.finditer(r"\{([0-9+\-()]+),([0-9+\-()]+)\}", body):
        ranges.append((eval_arith(match.group(1)), eval_arith(match.group(2))))
    if not ranges:
        raise ValueError("could not parse swap ranges")
    return ranges


def apply_swap_ranges(entries: list[str], ranges: list[tuple[int, int]]) -> list[str]:
    result = entries[:]
    for left, right in ranges:
        left -= 1
        right -= 1
        while left < right:
            result[left], result[right] = result[right], result[left]
            left += 1
            right -= 1
    return result


def parse_custom_b64_alphabet(src: str, table_end: int) -> str:
    marker = "do local I={"
    start = src.find(marker, table_end)
    if start == -1:
        raise ValueError("could not find custom alphabet table")
    brace_start = src.find("{", start)
    body, _ = extract_braced(src, brace_start)

    mapping: dict[str, int] = {}
    pattern = re.compile(r'(?P<key>\["(?:\\.|[^"])*"\]|[A-Za-z_][A-Za-z0-9_]*)=(?P<expr>[0-9+\-()]+)')
    for match in pattern.finditer(body):
        raw_key = match.group("key")
        if raw_key.startswith('["'):
            key = decode_lua_string_body(raw_key[2:-2]).decode("latin-1")
        else:
            key = raw_key
        mapping[key] = eval_arith(match.group("expr"))

    alphabet_by_value = {value: key for key, value in mapping.items()}
    if sorted(alphabet_by_value) != list(range(64)):
        raise ValueError("custom alphabet table does not cover 0..63")
    return "".join(alphabet_by_value[i] for i in range(64))


def custom_b64_decode(token: str, alphabet: str) -> bytes:
    mapping = {ch: i for i, ch in enumerate(alphabet)}
    out = bytearray()
    acc = 0
    chunk_pos = 0
    for idx, ch in enumerate(token):
        if ch in mapping:
            acc += mapping[ch] * (64 ** (3 - chunk_pos))
            chunk_pos += 1
            if chunk_pos == 4:
                out.extend(((acc // 65536) & 0xFF, ((acc % 65536) // 256) & 0xFF, acc % 256))
                acc = 0
                chunk_pos = 0
            continue
        if ch == "=":
            out.append((acc // 65536) & 0xFF)
            if idx + 1 >= len(token) or token[idx + 1] != "=":
                out.append(((acc % 65536) // 256) & 0xFF)
            break
    return bytes(out)


def preview_bytes(data: bytes, limit: int = 80) -> str:
    preview = []
    for b in data[:limit]:
        if 32 <= b < 127:
            preview.append(chr(b))
        elif b == 9:
            preview.append("\\t")
        elif b == 10:
            preview.append("\\n")
        elif b == 13:
            preview.append("\\r")
        else:
            preview.append(f"\\x{b:02x}")
    if len(data) > limit:
        preview.append("...")
    return "".join(preview)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return printable / len(data)


def summarize_entry(index: int, escaped_body: str) -> dict:
    decoded = decode_lua_string_body(escaped_body)
    ascii_text = decoded.decode("latin-1")

    base64_bytes = None
    if len(ascii_text) % 4 == 0 and BASE64_RE.fullmatch(ascii_text):
        try:
            base64_bytes = base64.b64decode(ascii_text, validate=True)
        except Exception:
            base64_bytes = None

    return {
        "index": index,
        "escaped_body": escaped_body,
        "decoded_text": ascii_text,
        "decoded_hex": decoded.hex(),
        "decoded_len": len(decoded),
        "decoded_printable_ratio": round(printable_ratio(decoded), 4),
        "looks_base64": base64_bytes is not None,
        "base64_hex": base64_bytes.hex() if base64_bytes is not None else None,
        "base64_ascii_preview": (
            "".join(chr(b) if 32 <= b < 127 else "." for b in base64_bytes[:64])
            if base64_bytes is not None
            else None
        ),
        "base64_len": len(base64_bytes) if base64_bytes is not None else None,
        "base64_printable_ratio": (
            round(printable_ratio(base64_bytes), 4) if base64_bytes is not None else None
        ),
    }


def build_text_report(entries: list[dict]) -> str:
    lines = [
        f"entries: {len(entries)}",
        f"base64-like entries: {sum(1 for entry in entries if entry['looks_base64'])}",
        "",
    ]
    for entry in entries:
        lines.append(
            f"[{entry['index']:04d}] text={entry['decoded_text']} "
            f"| hex={entry['decoded_hex']} "
            f"| base64={entry['looks_base64']}"
        )
        if entry["looks_base64"]:
            lines.append(
                f"       b64_hex={entry['base64_hex']} "
                f"| b64_ascii={entry['base64_ascii_preview']}"
            )
    return "\n".join(lines) + "\n"


def summarize_stage2_entry(index: int, escaped_body: str, stage1_text: str, stage2_bytes: bytes) -> dict:
    return {
        "index": index,
        "escaped_body": escaped_body,
        "stage1_text": stage1_text,
        "stage2_hex": stage2_bytes.hex(),
        "stage2_len": len(stage2_bytes),
        "stage2_printable_ratio": round(printable_ratio(stage2_bytes), 4),
        "stage2_preview": preview_bytes(stage2_bytes),
    }


def build_stage2_report(entries: list[dict], alphabet: str, swap_ranges: list[tuple[int, int]]) -> str:
    lines = [
        f"entries: {len(entries)}",
        f"alphabet: {alphabet}",
        f"swap_ranges: {swap_ranges}",
        f"stage2_printable_gt_0_8: {sum(1 for entry in entries if entry['stage2_printable_ratio'] > 0.8)}",
        "",
    ]
    for entry in entries:
        lines.append(
            f"[{entry['index']:04d}] stage1={entry['stage1_text']} "
            f"| len={entry['stage2_len']} "
            f"| printable={entry['stage2_printable_ratio']} "
            f"| preview={entry['stage2_preview']}"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and decode the Lua string pool.")
    parser.add_argument(
        "--input",
        default="/Users/kanishkv/Developer/wcue deobf/source.lua",
        help="Path to the obfuscated Lua file.",
    )
    parser.add_argument(
        "--out-dir",
        default="/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts",
        help="Directory for extracted artifacts.",
    )
    args = parser.parse_args()

    source_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    src = source_path.read_text(encoding="utf-8")
    raw_entries = find_string_pool(src)
    marker_index = src.find("local H={")
    if marker_index == -1:
        raise ValueError("could not find string pool marker")
    table_start = src.find("{", marker_index)
    _, table_end = extract_braced(src, table_start)

    entries = [summarize_entry(i + 1, body) for i, body in enumerate(raw_entries)]
    swap_ranges = parse_swap_ranges(src, table_end)
    alphabet = parse_custom_b64_alphabet(src, table_end)

    swapped_raw_entries = apply_swap_ranges(raw_entries, swap_ranges)
    stage2_entries = []
    for index, escaped_body in enumerate(swapped_raw_entries, start=1):
        stage1_text = decode_lua_string_body(escaped_body).decode("latin-1")
        stage2_bytes = custom_b64_decode(stage1_text, alphabet)
        stage2_entries.append(summarize_stage2_entry(index, escaped_body, stage1_text, stage2_bytes))

    (out_dir / "string_pool.json").write_text(
        json.dumps(entries, indent=2),
        encoding="utf-8",
    )
    (out_dir / "string_pool.txt").write_text(
        build_text_report(entries),
        encoding="utf-8",
    )
    (out_dir / "string_pool_stage2.json").write_text(
        json.dumps(stage2_entries, indent=2),
        encoding="utf-8",
    )
    (out_dir / "string_pool_stage2.txt").write_text(
        build_stage2_report(stage2_entries, alphabet, swap_ranges),
        encoding="utf-8",
    )
    (out_dir / "string_pool_meta.json").write_text(
        json.dumps(
            {
                "swap_ranges": swap_ranges,
                "custom_b64_alphabet": alphabet,
                "entry_count": len(raw_entries),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"wrote {len(entries)} entries to {out_dir}")


if __name__ == "__main__":
    main()
