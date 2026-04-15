#!/usr/bin/env python3
"""
Annotate the ORIGINAL source.lua with decoded string values.

Also applies to all helper files that contain I() references.
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

    # Annotate the source file
    source_path = BASE / "../source.lua"
    source = source_path.read_text()
    print(f"Source size: {len(source)} chars")

    # Pattern for hex-annotated I() calls
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

    print(f"\nReplacements in source.lua:")
    print(f"  Hex-annotated (CONFIDENT/LIKELY): {hex_replaced}")
    print(f"  Hex-annotated (uncertain): {hex_uncertain}")
    print(f"  Named strings: {named_replaced}")

    out_path = BASE / "artifacts/source_annotated.lua"
    with open(out_path, "w") as f:
        f.write(result2)
    print(f"\nAnnotated source written to {out_path}")
    print(f"Size: {len(result2)} chars")

    # Also annotate the annotated source file from earlier (it already has some annotations)
    disp_path = BASE / "artifacts/vm_wrappers/helper_21_a_annotated.lua"
    disp = disp_path.read_text()

    hex_replaced2 = 0
    hex_uncertain2 = 0
    named_replaced2 = 0

    def replace_hex2(m):
        nonlocal hex_replaced2, hex_uncertain2
        h_index = int(m.group(2))
        if h_index in decoded:
            info = decoded[h_index]
            hex_replaced2 += 1
            conf = info["confidence"]
            return f"{lua_escape(info['string'])}--[[H[{h_index}] {conf}]]"
        else:
            hex_uncertain2 += 1
            return m.group(0)

    def replace_named2(m):
        nonlocal named_replaced2
        h_index = int(m.group(2))
        name = m.group(3)
        if name and not name.startswith("hex:"):
            named_replaced2 += 1
            return f'"{name}"--[[H[{h_index}]]]'
        return m.group(0)

    result3 = hex_pattern.sub(replace_hex2, disp)
    result4 = named_pattern.sub(replace_named2, result3)

    print(f"\nAdditional replacements in dispatcher:")
    print(f"  Hex-annotated: {hex_replaced2}")
    print(f"  Hex-annotated (uncertain): {hex_uncertain2}")
    print(f"  Named strings: {named_replaced2}")

    out_path2 = BASE / "artifacts/vm_wrappers/helper_21_a_full_annotated.lua"
    with open(out_path2, "w") as f:
        f.write(result4)
    print(f"\nFully annotated dispatcher written to {out_path2}")
    print(f"Size: {len(result4)} chars")


if __name__ == "__main__":
    main()
