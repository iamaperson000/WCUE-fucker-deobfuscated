#!/usr/bin/env python3
"""
Annotate the source_i_annotated.lua with decoded string values.
This file already has I() annotations in the format I(expr)--[[H[N]=name_or_hex]].
"""

import json
import re
from pathlib import Path

BASE = Path("/Users/kanishkv/Developer/wcue deobf/wcue-decompile")


def load_decoded():
    with open(BASE / "artifacts/decoded_strings_lookup.json") as f:
        data = json.load(f)
    result = {}
    for k, v in data.items():
        idx = int(k)
        result[idx] = v
    return result


def lua_escape(s):
    if not s:
        return '""'
    needs_escape = any(c in s for c in ("\n", "\r", "\0", "\\", '"', "'"))
    if needs_escape:
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
    decoded = load_decoded()
    print(f"Loaded {len(decoded)} decoded strings")

    source = (BASE / "artifacts/source_i_annotated.lua").read_text()
    print(f"Source size: {len(source)} chars")

    # Pattern for hex-annotated I() calls (with nested parens)
    hex_pattern = re.compile(
        r"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=hex:([0-9a-fA-F]+)\]\]"
    )

    # Pattern for named I() calls
    named_pattern = re.compile(
        r"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=([^\]]*?)\]\]"
    )

    hex_replaced = 0
    hex_uncertain = 0
    named_replaced = 0

    def replace_hex(m):
        nonlocal hex_replaced, hex_uncertain
        h_index = int(m.group(2))
        if h_index in decoded:
            info = decoded[h_index]
            hex_replaced += 1
            conf = info["confidence"]
            return f"{lua_escape(info['string'])}--[[H[{h_index}] {conf}]]"
        else:
            hex_uncertain += 1
            return m.group(0)

    def replace_named(m):
        nonlocal named_replaced
        h_index = int(m.group(2))
        name = m.group(3)
        if name and not name.startswith("hex:"):
            named_replaced += 1
            return f'"{name}"--[[H[{h_index}]]]'
        return m.group(0)

    result = hex_pattern.sub(replace_hex, source)
    result2 = named_pattern.sub(replace_named, result)

    print(f"\nReplacements:")
    print(f"  Hex-annotated (decoded): {hex_replaced}")
    print(f"  Hex-annotated (uncertain): {hex_uncertain}")
    print(f"  Named strings: {named_replaced}")

    out_path = BASE / "artifacts/source_deobfuscated.lua"
    with open(out_path, "w") as f:
        f.write(result2)
    print(f"\nDeobfuscated source written to {out_path}")
    print(f"Size: {len(result2)} chars")


if __name__ == "__main__":
    main()
