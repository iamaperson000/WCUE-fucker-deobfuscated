#!/usr/bin/env python3
"""
Bulk decode ALL hidden strings - v3.

Strategy:
1. Find all I() calls with hex annotations → (H_index, position)
2. Find ALL seed-like arithmetic expressions → (evaluated_value, position)
3. For each I() reference, collect ALL nearby seed candidates
4. For each unique H index, try ALL candidate seeds from ALL occurrences
5. Pick the seed that gives the best printable ratio
6. For still-unmatched H indices, try ALL seed candidates in the entire file
"""

import json
import re
import math
from pathlib import Path
from collections import defaultdict

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


def printable_ratio(s):
    if not s:
        return 0.0
    return sum(1 for c in s if 32 <= ord(c) < 127 or c in "\t\n\r") / len(s)


def find_hex_i_refs(text):
    # Handle nested parens in I() expressions like I(-719083-(-701541))
    # Pattern matches I(...) followed by --[[H[N]=hex:HEX]]
    # The inner expression can contain one level of nested parens
    pattern = r"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=hex:([0-9a-fA-F]+)\]\]"
    results = []
    for m in re.finditer(pattern, text):
        h_index = int(m.group(2))
        hex_val = m.group(3)
        pos = m.start()
        results.append((h_index, hex_val, pos))
    return results


def find_seed_candidates(text):
    candidates = []

    # Compound expressions: number op number or number op (-number) or negative number op number
    # Match: DIGITS (spaces? op spaces? (optional minus/parens) DIGITS)
    # Also handle -DIGITS op DIGITS

    # Pattern for compound arithmetic: captures things like:
    # 11774872618684-799057
    # 32787479085778-(-30929)
    # -825091+28937375910822
    # 286925+8939089801077
    # 92871+21369477790743
    compound = re.compile(
        r"(?<![0-9a-fA-Fx])"  # Not preceded by hex digit or 'x'
        r"(-?\d{1,14})"  # First operand (possibly negative)
        r"(\s*[+\-]\s*\(?"  # Operator, possibly with opening paren
        r"-?"  # Possibly negative second operand
        r"\d{1,14}"  # Second operand
        r"\)?)"  # Optionally closing paren
        r"(?![0-9a-fA-Fx])"  # Not followed by hex digit
    )

    seen_positions = set()
    for m in re.finditer(compound, text):
        expr = m.group(0).replace(" ", "")
        # Skip if inside I() expression or H[] annotation
        # Check we're not inside --[[ ]]] comment
        before = text[: m.start()]
        comment_depth = before.count("[[") - before.count("]]")
        if comment_depth > 0:
            continue

        try:
            val = int(eval(expr))
        except:
            continue

        if 1_000_000_000 <= abs(val) <= 99_999_999_999_999:
            candidates.append((val, m.start(), m.end(), expr))
            seen_positions.add((m.start(), m.end()))

    # Bare large numbers (not part of compound expressions)
    bare = re.compile(
        r"(?<![0-9a-fA-Fx\-])"
        r"(\d{10,14})"
        r"(?![0-9a-fA-Fx])"
    )

    for m in re.finditer(bare, text):
        # Skip if inside comment
        before = text[: m.start()]
        comment_depth = before.count("[[") - before.count("]]")
        if comment_depth > 0:
            continue

        # Skip if part of already-found compound expression
        if any(m.start() >= c[1] and m.start() < c[2] for c in candidates):
            continue

        val = int(m.group(1))
        if 1_000_000_000 <= val <= 99_999_999_999_999:
            candidates.append((val, m.start(), m.end(), str(val)))

    return candidates


def main():
    pool = load_stage2_pool()
    print(f"Loaded {len(pool)} stage-2 entries")

    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()
    print(f"Dispatcher size: {len(dispatcher)} chars")

    hex_refs = find_hex_i_refs(dispatcher)
    print(f"Found {len(hex_refs)} hex-annotated I() references")

    unique_indices = set(h for h, _, _ in hex_refs)
    print(f"Unique H indices with hex blobs: {len(unique_indices)}")

    seed_candidates = find_seed_candidates(dispatcher)
    print(f"Found {len(seed_candidates)} seed candidates")

    # Build position-sorted lists for fast lookup
    seed_by_pos = sorted(seed_candidates, key=lambda x: x[1])

    # For each hex I() ref, find ALL seed candidates within a window
    # Then for each unique H index, collect ALL candidate seeds from ALL occurrences
    WINDOW = 500

    # Map: h_index -> set of (seed_value, distance)
    h_candidates = defaultdict(set)

    for h_index, hex_val, ref_pos in hex_refs:
        for seed_val, seed_start, seed_end, seed_expr in seed_candidates:
            dist = abs(seed_start - ref_pos)
            if dist <= WINDOW:
                h_candidates[h_index].add((seed_val, dist))

    print(f"H indices with at least one candidate seed: {len(h_candidates)}")
    print(
        f"H indices with NO candidate seed: {len(unique_indices - set(h_candidates.keys()))}"
    )

    # Known verified pairs
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
    }

    # For each H index, try all candidate seeds and pick the best
    results = {}
    no_candidates = []

    for h_index in sorted(unique_indices):
        blob = get_blob(pool, h_index)
        if blob is None:
            continue

        # Override with known pairs
        if h_index in known_pairs:
            seed = known_pairs[h_index]
            decoded = decode_blob(blob, seed)
            if decoded is not None:
                p = printable_ratio(decoded)
                results[h_index] = {
                    "seed": seed,
                    "decoded": decoded,
                    "printable_ratio": p,
                    "length": len(decoded),
                    "verified": True,
                }
                continue

        candidates = h_candidates.get(h_index, set())
        if not candidates:
            no_candidates.append(h_index)
            continue

        # Try all candidate seeds and pick the best
        best_result = None
        best_printable = -1
        best_seed = None
        best_dist = None

        # Sort candidates by distance (try closest first, but check all)
        for seed, dist in sorted(candidates, key=lambda x: x[1]):
            try:
                decoded = decode_blob(blob, seed)
                if decoded is None:
                    continue
                p = printable_ratio(decoded)
                if p > best_printable:
                    best_printable = p
                    best_result = decoded
                    best_seed = seed
                    best_dist = dist
                    # If perfect decode, stop early
                    if p >= 0.95:
                        break
            except:
                continue

        if best_result is not None:
            results[h_index] = {
                "seed": best_seed,
                "decoded": best_result,
                "printable_ratio": best_printable,
                "length": len(best_result),
                "best_distance": best_dist,
            }

    print(
        f"\nNo candidates for {len(no_candidates)} H indices: {no_candidates[:20]}..."
    )

    # For H indices with no candidates, try ALL seeds in the file
    if no_candidates:
        print(
            f"\nTrying global seed search for {len(no_candidates)} unmatched indices..."
        )
        all_seeds = list(set(c[0] for c in seed_candidates))
        print(f"  {len(all_seeds)} unique candidate seeds to try per blob")

        # This is slow so only try for small blobs (< 50 bytes)
        for h_index in no_candidates:
            blob = get_blob(pool, h_index)
            if blob is None or len(blob) > 50:
                continue

            best_result = None
            best_printable = -1
            best_seed = None

            for seed in all_seeds:
                try:
                    decoded = decode_blob(blob, seed)
                    if decoded is None:
                        continue
                    p = printable_ratio(decoded)
                    if p > best_printable:
                        best_printable = p
                        best_result = decoded
                        best_seed = seed
                        if p >= 0.95:
                            break
                except:
                    continue

            if best_result is not None and best_printable >= 0.5:
                results[h_index] = {
                    "seed": best_seed,
                    "decoded": best_result,
                    "printable_ratio": best_printable,
                    "length": len(best_result),
                    "best_distance": -1,  # global search
                }

    # Summary
    good = sum(1 for r in results.values() if r["printable_ratio"] >= 0.8)
    ok = sum(1 for r in results.values() if 0.4 <= r["printable_ratio"] < 0.8)
    bad = sum(1 for r in results.values() if r["printable_ratio"] < 0.4)

    print(f"\n=== Decode Results ===")
    print(f"Total decoded: {len(results)}")
    print(f"Fully decoded (>=80% printable): {good}")
    print(f"Partially decoded (40-80%): {ok}")
    print(f"Failed (<40%): {bad}")
    print(f"Missing (no result): {len(unique_indices) - len(results)}")

    # Show samples
    print(f"\n=== Good Decodes (printable >= 0.9) ===")
    samples = [(k, v) for k, v in results.items() if v["printable_ratio"] >= 0.9]
    samples.sort(key=lambda x: x[0])
    for h_idx, r in samples[:40]:
        display = r["decoded"][:60]
        if len(r["decoded"]) > 60:
            display += "..."
        print(f'  H[{h_idx}] seed={r["seed"]} "{display}"')

    # Show failed for debugging
    print(f"\n=== Failed Decodes (printable < 0.3) ===")
    failed = [(k, v) for k, v in results.items() if v["printable_ratio"] < 0.3]
    failed.sort(key=lambda x: x[0])
    for h_idx, r in failed[:15]:
        display = "".join(
            c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in r["decoded"][:40]
        )
        print(f'  H[{h_idx}] seed={r["seed"]} "{display}"')

    # Save results
    output = {}
    for h_idx, r in sorted(results.items()):
        output[str(h_idx)] = {
            "seed": r["seed"],
            "decoded": r["decoded"],
            "printable_ratio": r["printable_ratio"],
            "length": r["length"],
        }

    out_path = BASE / "artifacts" / "decoded_hidden_strings_v3.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
