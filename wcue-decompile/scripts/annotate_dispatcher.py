#!/usr/bin/env python3
"""
Annotate the WCUE dispatcher with decoded string values.

Strategies:
1. Replace hex-annotated I() calls where we have a confident decode (printable >= 0.85)
2. Replace named I() calls (non-hex) with their known string values
3. Leave uncertain decodes as-is but add a comment marker

Output: annotated dispatcher file with I() calls replaced by string literals
"""

import json
import re
from pathlib import Path

BASE = Path("/Users/kanishkv/Developer/wcue deobf/wcue-decompile")


def load_decoded_strings():
    with open(BASE / "artifacts/decoded_hidden_strings_v3.json") as f:
        data = json.load(f)
    result = {}
    for k, v in data.items():
        idx = int(k)
        result[idx] = {
            "decoded": v["decoded"],
            "printable_ratio": v["printable_ratio"],
            "seed": v["seed"],
            "length": v["length"],
        }
    return result


def load_pool():
    with open(BASE / "artifacts/string_pool_stage2.json") as f:
        return json.load(f)


def ror32(val, shift):
    shift = shift % 32
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF


def decode_blob(blob: bytes, seed: int) -> str:
    state45 = seed % (2**45)
    state257 = (seed % 255) + 2
    if state257 == 1:
        state257 = 2
    running_offset = 101
    queue = []
    result = []
    for byte_val in blob:
        if not queue:
            while True:
                state45 = (state45 * 177 + 5746771741299) % (2**45)
                state257 = (state257 * 80) % 257
                if state257 == 1:
                    continue
                shift1 = 13 - (state257 // 32)
                if shift1 < 0:
                    shift1 = 0
                T = state45 >> shift1
                R = T & 0xFFFFFFFF
                shift2 = state257 % 32
                rotated = ror32(R, shift2)
                byte0 = rotated & 0xFF
                byte1 = (rotated >> 8) & 0xFF
                byte2 = (rotated >> 16) & 0xFF
                byte3 = (rotated >> 24) & 0xFF
                queue = [byte0, byte1, byte2, byte3]
                break
        random_byte = queue.pop()
        decoded = (byte_val + random_byte + running_offset) % 256
        running_offset = decoded
        result.append(chr(decoded))
    return "".join(result)


def lua_escape_string(s):
    if not s:
        return '""'
    needs_long = False
    for c in s:
        if c == "\n" or c == "\r" or c == "\0" or c == "\\" or c == '"':
            needs_long = True
            break
    if needs_long:
        escaped = (
            s.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\0", "\\0")
        )
        return f'"{escaped}"'
    return f'"{s}"'


def main():
    decoded = load_decoded_strings()
    pool = load_pool()
    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()
    print(f"Dispatcher size: {len(dispatcher)} chars")
    print(f"Loaded {len(decoded)} decoded strings")

    # Build H index to decoded string map (only high-confidence)
    h_to_string = {}
    h_to_printable = {}
    for idx, info in decoded.items():
        if info["printable_ratio"] >= 0.85:
            h_to_string[idx] = info["decoded"]
            h_to_printable[idx] = info["printable_ratio"]

    # Also add named strings from the pool (these are already decoded in stage 2)
    for i, entry in enumerate(pool):
        idx = i + 1
        if idx not in h_to_string:
            # Check if this entry has a known plaintext value
            hex_val = entry.get("stage2_hex", "")
            if not hex_val or len(hex_val) <= 4:
                # Very short entries might be simple names
                pass

    # Count replacements by type
    hex_replaced = 0
    hex_uncertain = 0
    named_replaced = 0

    # Pattern for hex-annotated I() calls (with nested parens support)
    hex_pattern = re.compile(
        r"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=hex:([0-9a-fA-F]+)\]\]"
    )

    # Pattern for named I() calls
    named_pattern = re.compile(
        r"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=([^\]]*?)\]\]"
    )

    # First pass: replace hex-annotated I() calls
    def replace_hex(m):
        nonlocal hex_replaced, hex_uncertain
        h_index = int(m.group(2))
        hex_val = m.group(3)

        if h_index in h_to_string:
            s = h_to_string[h_index]
            hex_replaced += 1
            pr = h_to_printable[h_index]
            confidence = "CONFIDENT" if pr >= 0.95 else "LIKELY"
            return f"{lua_escape_string(s)}--[[H[{h_index}] {confidence}]]"
        else:
            hex_uncertain += 1
            return m.group(0)  # Leave unchanged

    result = hex_pattern.sub(replace_hex, dispatcher)

    # Second pass: replace named I() calls (non-hex)
    def replace_named(m):
        nonlocal named_replaced
        expr = m.group(1)
        h_index = int(m.group(2))
        name = m.group(3)

        if name and not name.startswith("hex:"):
            named_replaced += 1
            return f'"{name}"--[[H[{h_index}]]]'
        return m.group(0)

    # Only replace named annotations that aren't empty
    result2 = named_pattern.sub(replace_named, result)

    print(f"\nReplacements:")
    print(f"  Hex-annotated (CONFIDENT/LIKELY): {hex_replaced}")
    print(f"  Hex-annotated (uncertain): {hex_uncertain}")
    print(f"  Named strings: {named_replaced}")

    # Write the annotated dispatcher
    out_path = BASE / "artifacts/vm_wrappers/helper_21_a_annotated.lua"
    with open(out_path, "w") as f:
        f.write(result2)
    print(f"\nAnnotated dispatcher written to {out_path}")
    print(f"Size: {len(result2)} chars")

    # Also build and save the decoded strings lookup table
    lookup = {}
    for idx, info in sorted(decoded.items()):
        if info["printable_ratio"] >= 0.85:
            lookup[str(idx)] = {
                "string": info["decoded"],
                "printable_ratio": info["printable_ratio"],
                "seed": info["seed"],
                "confidence": "CONFIDENT"
                if info["printable_ratio"] >= 0.95
                else "LIKELY",
            }
        elif info["printable_ratio"] >= 0.4:
            lookup[str(idx)] = {
                "string": info["decoded"],
                "printable_ratio": info["printable_ratio"],
                "seed": info["seed"],
                "confidence": "UNCERTAIN",
            }

    lookup_path = BASE / "artifacts/decoded_strings_lookup.json"
    with open(lookup_path, "w") as f:
        json.dump(lookup, f, indent=2, ensure_ascii=False)
    print(f"Decoded strings lookup written to {lookup_path}")
    print(
        f"  CONFIDENT/LIKELY: {sum(1 for v in lookup.values() if v['confidence'] in ('CONFIDENT', 'LIKELY'))}"
    )
    print(
        f"  UNCERTAIN: {sum(1 for v in lookup.values() if v['confidence'] == 'UNCERTAIN')}"
    )


if __name__ == "__main__":
    main()
