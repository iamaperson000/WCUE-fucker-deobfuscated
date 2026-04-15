#!/usr/bin/env python3
"""
Bulk decode ALL hidden strings in the WCUE dispatcher.

Scans helper_21_a.lua for all W[J](H[idx], seed) patterns,
extracts the (H_index, seed) pairs, and decodes them.
"""

import json
import math
import re
from pathlib import Path

BASE = Path("/Users/kanishkv/Developer/wcue deobf/wcue-decompile")


def load_stage2_pool():
    with open(BASE / "artifacts/string_pool_stage2.json") as f:
        return json.load(f)


def get_blob(pool, h_index):
    if h_index < 1 or h_index > len(pool):
        return None
    entry = pool[h_index - 1]
    return bytes.fromhex(entry["stage2_hex"])


def ror32(val, shift):
    shift = shift % 32
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF


def decode_blob(blob: bytes, seed: int) -> str:
    state45 = seed % (2**45)
    state257 = (seed % 255) + 2
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


def main():
    pool = load_stage2_pool()
    print(f"Loaded {len(pool)} stage-2 entries")

    # Read the dispatcher to find all (H_index, seed) pairs
    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()

    # Also read the annotated source for I() annotations
    annotated = (BASE / "artifacts/source_i_annotated.lua").read_text()

    # First, build a map of H_index -> human-readable from I() annotations
    # These are entries that decode directly (non-blob strings)
    known_strings = {}
    for match in re.finditer(
        r"I\(([0-9+\-() ]+)\)--\[\[H\[(\d+)\]=([^]]+)\]\]", annotated
    ):
        try:
            index = int(match.group(2))
            value = match.group(3)
            if not value.startswith("hex:"):
                known_strings[index] = value
        except Exception:
            pass

    print(f"Found {len(known_strings)} known plaintext strings")

    # Now find all blob references in the dispatcher
    # Pattern: d(H[idx], seed) where d is a decoder closure variable
    # These appear as: var=I(expr)--[[H[N]=hex:...]] followed by seed usage
    # Or more directly: W[J](H[idx], seed) patterns

    # Find all H index + seed pairs that are passed to decoder closures
    # The pattern is: H[I(expr)] where I(expr) is annotated with hex:xxxxxxxx
    # And then a nearby seed value (large number)

    # Actually, the cleanest approach: find all I() annotations that have hex:... values
    # These are the hidden strings. Then find the seed that accompanies them.

    # The dispatcher uses patterns like:
    #   var=I(expr)--[[H[N]=hex:xxxx]]
    #   ...
    #   other_var=decoder_call(H, seed)
    # where the seed is a nearby large number

    # But the W[J] decoder calls use the blob directly:
    #   d=Q(H, seed)  or  h=Q(o, h)  etc.
    # where Q is the decoder closure and the first arg is from H[]

    # Let's just scan for all hex-annotated H references and check if they appear
    # in a decoder context with a nearby seed

    # Find all hex-annotated I() calls in the dispatcher
    hex_pattern = r"I\(([0-9+\-() ]+)\)--\[\[H\[(\d+)\]=hex:([0-9a-f]+)\]\]"
    hex_refs = []
    for match in re.finditer(hex_pattern, dispatcher):
        index = int(match.group(2))
        hex_val = match.group(3)
        hex_refs.append((index, hex_val, match.start()))

    print(f"Found {len(hex_refs)} hex-annotated H references in dispatcher")

    # For each hex reference, find the nearest large number that could be a seed
    # Seeds are typically 12-14 digit numbers
    blob_seeds = {}
    for idx, hex_val, pos in hex_refs:
        # Look in a window after this reference for a large number
        window = dispatcher[pos : pos + 500]
        # Find large numbers (potential seeds)
        seed_matches = re.findall(r"(?<![0-9a-f])([0-9]{10,15})(?![0-9a-f])", window)
        if seed_matches:
            # The first large number that looks like a seed (not an I() offset)
            for s in seed_matches:
                try:
                    seed_val = int(s)
                    if 1000000000 <= seed_val <= 99999999999999:
                        blob_seeds[idx] = (seed_val, hex_val)
                        break
                except ValueError:
                    continue

    print(f"Found {len(blob_seeds)} (H_index, seed) pairs from direct context")

    # Now also use the specific pairs from Phase Four that we know work
    known_pairs = {
        2772: 2496212501642,
        4854: 1186289386024,
        3204: 30916575737916,
        5619: 32879211232206,
        693: 17652829380636,
        2704: 14670855527087,
        1542: 3007687984504,
        3869: 11301675111566,
        942: 3732199540425,
        2271: 2668542641370,
        3615: 19901264536627,
        5641: 14043772639627,
        5897: 33213205888106,
        6860: 2711126017262,
        2811: 3575791224449,
        106: 2711126017262,
    }

    # Merge known pairs
    all_pairs = {**blob_seeds}
    for idx, seed in known_pairs.items():
        if idx not in all_pairs or all_pairs[idx][0] != seed:
            all_pairs[idx] = (
                seed,
                pool[idx - 1]["stage2_hex"] if idx <= len(pool) else "",
            )

    print(f"\nTotal pairs to decode: {len(all_pairs)}")

    # Decode all
    results = {}
    for h_idx, (seed, hex_val) in sorted(all_pairs.items()):
        blob = get_blob(pool, h_idx)
        if blob is None:
            continue
        try:
            decoded = decode_blob(blob, seed)
            printable = sum(
                1 for c in decoded if 32 <= ord(c) < 127 or c in "\t\n\r"
            ) / max(len(decoded), 1)
            results[h_idx] = (seed, decoded, printable)
        except Exception as e:
            results[h_idx] = (seed, f"ERROR: {e}", 0)

    # Also decode using known_pairs directly
    for h_idx, seed in known_pairs.items():
        blob = get_blob(pool, h_idx)
        if blob is None:
            continue
        if h_idx in results:
            continue
        try:
            decoded = decode_blob(blob, seed)
            printable = sum(
                1 for c in decoded if 32 <= ord(c) < 127 or c in "\t\n\r"
            ) / max(len(decoded), 1)
            results[h_idx] = (seed, decoded, printable)
        except Exception as e:
            results[h_idx] = (seed, f"ERROR: {e}", 0)

    # Print results sorted by H index
    print(f"\n{'H[idx]':<10} {'seed':<20} {'len':<5} {'p':<5} {'result'}")
    print("-" * 90)

    fully_decoded = 0
    partially_decoded = 0
    for h_idx in sorted(results.keys()):
        seed, decoded, printable = results[h_idx]
        display = "".join(
            c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in decoded[:60]
        )
        if len(decoded) > 60:
            display += "..."
        p_str = f"{printable:.2f}"
        print(f'H[{h_idx}]{"":<5} {seed:<20} {len(decoded):<5} {p_str:<5} "{display}"')
        if printable >= 0.8:
            fully_decoded += 1
        elif printable >= 0.4:
            partially_decoded += 1

    print(f"\nFully decoded (>=80% printable): {fully_decoded}")
    print(f"Partially decoded (40-80%): {partially_decoded}")
    print(f"Total decoded: {len(results)}")

    # Save results to JSON for further use
    output = {}
    for h_idx in sorted(results.keys()):
        seed, decoded, printable = results[h_idx]
        output[str(h_idx)] = {
            "seed": seed,
            "decoded": decoded,
            "printable_ratio": printable,
            "length": len(decoded),
        }

    out_path = BASE / "artifacts" / "decoded_hidden_strings.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
