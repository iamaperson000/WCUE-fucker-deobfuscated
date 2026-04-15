#!/usr/bin/env python3
"""
Bulk decode ALL hidden strings in the WCUE dispatcher - v2.

Strategy:
1. Find all I() calls with hex annotations → (H_index, position)
2. Find all seed-like arithmetic expressions → (evaluated_value, position)
3. Match each hex blob to its nearest seed candidate
4. Decode and validate by printable ratio
5. For unmatched or failed matches, try a wider search
"""

import json
import re
import math
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
    if state257 == 1:
        return None
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
    """Find all I() calls with hex annotations."""
    pattern = r"I\(([^)]+)\)--\[\[H\[(\d+)\]=hex:([0-9a-fA-F]+)\]\]"
    results = []
    for m in re.finditer(pattern, text):
        expr = m.group(1)
        h_index = int(m.group(2))
        hex_val = m.group(3)
        pos = m.start()
        results.append((h_index, hex_val, pos))
    return results


def eval_arith_expr(expr):
    """Evaluate a simple arithmetic expression like '12345-6789' or '12+34567890123456'."""
    expr = expr.strip()
    # Handle double negative: BIG-(-SMALL) → BIG+SMALL
    # And regular subtraction/addition
    try:
        # Replace -(- with +
        cleaned = expr.replace("-(-", "+(").replace("--", "+")
        # Handle patterns like: number+number, number-number
        # But we need to be careful with precedence
        result = eval(expr)
        if isinstance(result, (int, float)) and not math.isinf(result):
            return int(result)
    except:
        pass
    return None


def find_seed_candidates(text):
    """Find all arithmetic expressions that evaluate to large numbers (potential seeds)."""
    candidates = []

    # Pattern 1: BIG_NUMBER - small_number  (e.g., 11774872618684-799057)
    # Pattern 2: small_number + BIG_NUMBER  (e.g., 847771+25872560160628)
    # Pattern 3: BIG_NUMBER - (-small_number) (e.g., 32787479085778-(-30929))
    # Pattern 4: Bare large number (e.g., 3575791224449)

    # Match compound expressions: number op (-(number)) or number op number
    # where op is + or -
    seed_pattern = re.compile(
        r"(?<![0-9a-fA-Fx])"  # Not preceded by hex digit or x
        r"("
        r"-?\d+"  # First number (possibly negative)
        r"\s*[+\-]\s*"  # Operator
        r"\(?-?\d+\)?"  # Second number (possibly parenthesized/negative)
        r")"
        r"(?![0-9a-fA-Fx])"  # Not followed by hex digit
    )

    for m in re.finditer(seed_pattern, text):
        expr = m.group(1)
        # Clean up whitespace
        expr_clean = expr.replace(" ", "")
        val = eval_arith_expr(expr_clean)
        if val is not None and 1_000_000_000 <= abs(val) <= 99_999_999_999_999:
            candidates.append((val, m.start(), m.end(), expr_clean))

    # Also match bare large numbers (not part of expressions already found)
    # Pattern: standalone 10-14 digit number
    bare_pattern = re.compile(
        r"(?<![0-9a-fA-Fx])"
        r"(\d{10,14})"
        r"(?![0-9a-fA-Fx])"
    )
    existing_positions = set(c[1] for c in candidates)

    for m in re.finditer(bare_pattern, text):
        # Skip if this number is part of an already-found expression
        if any(abs(m.start() - c[1]) < len(str(c[3])) for c in candidates):
            continue
        val = int(m.group(1))
        if 1_000_000_000 <= val <= 99_999_999_999_999:
            candidates.append((val, m.start(), m.end(), str(val)))

    return candidates


def match_refs_to_seeds(hex_refs, seed_candidates, text, window=500):
    """Match each hex I() reference to its nearest seed candidate."""
    matches = {}

    for h_index, hex_val, ref_pos in hex_refs:
        best_seed = None
        best_distance = window * 2  # Start beyond window
        best_printable = -1

        # Look in a window around the reference for seed candidates
        for seed_val, seed_start, seed_end, seed_expr in seed_candidates:
            # Check if seed is within window of this reference
            if seed_start < ref_pos - window or seed_start > ref_pos + window:
                continue

            distance = abs(seed_start - ref_pos)
            if distance > window:
                continue

            if distance < best_distance:
                best_seed = seed_val
                best_distance = distance
                best_printable = -1  # Will need to verify

        if best_seed is not None:
            matches[h_index] = (best_seed, hex_val, best_distance)

    return matches


def match_via_variable_flow(text, hex_refs, seed_candidates):
    """
    More sophisticated matching: trace variable assignments.
    In each VM instruction block, find assignments like var=I(hex) and var2=seed_expr
    then find func(var, var2) to confirm the pairing.
    """
    # This is a fallback for cases where proximity matching fails
    # For now, we'll use proximity as primary and variable tracing as secondary
    pass


def main():
    pool = load_stage2_pool()
    print(f"Loaded {len(pool)} stage-2 entries")

    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()
    print(f"Dispatcher size: {len(dispatcher)} chars")

    # Find all hex-annotated I() calls
    hex_refs = find_hex_i_refs(dispatcher)
    print(f"Found {len(hex_refs)} hex-annotated I() references")

    # Get unique H indices
    unique_indices = set(h for h, _, _ in hex_refs)
    print(f"Unique H indices with hex blobs: {len(unique_indices)}")

    # Find all seed candidates
    seed_candidates = find_seed_candidates(dispatcher)
    print(f"Found {len(seed_candidates)} seed candidates")

    # Show some seed examples for debugging
    print("\nSample seed candidates:")
    for val, start, end, expr in seed_candidates[:10]:
        print(f"  {expr} = {val} at pos {start}")

    # Known verified pairs (from Phase Four)
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

    # Match hex refs to seeds by proximity
    # Start with a small window and expand
    for window in [200, 500, 1000, 2000]:
        matches = match_refs_to_seeds(
            hex_refs, seed_candidates, dispatcher, window=window
        )
        matched_indices = set(matches.keys())
        unmatched = unique_indices - matched_indices
        print(
            f"\nWindow={window}: matched {len(matched_indices)} unique indices, {len(unmatched)} unmatched"
        )

        if len(unmatched) <= 50:
            print(f"  Unmatched H indices: {sorted(unmatched)[:50]}")
        else:
            print(f"  {len(unmatched)} unmatched indices")
        break  # Use first window size for now

    # Now decode all matched pairs
    results = {}
    ambiguous = 0

    # First handle matches by proximity
    for h_index, (seed, hex_val, distance) in matches.items():
        blob = get_blob(pool, h_index)
        if blob is None:
            continue

        try:
            decoded = decode_blob(blob, seed)
            if decoded is None:
                continue
            p = printable_ratio(decoded)
            results[h_index] = {
                "seed": seed,
                "decoded": decoded,
                "printable_ratio": p,
                "length": len(decoded),
                "hex": hex_val,
                "match_distance": distance,
            }
        except Exception as e:
            results[h_index] = {
                "seed": seed,
                "decoded": f"ERROR: {e}",
                "printable_ratio": 0,
                "length": 0,
                "hex": hex_val,
                "match_distance": distance,
            }

    # Override with known verified pairs
    for h_index, seed in known_pairs.items():
        blob = get_blob(pool, h_index)
        if blob is None:
            continue
        decoded = decode_blob(blob, seed)
        if decoded is None:
            continue
        p = printable_ratio(decoded)
        results[h_index] = {
            "seed": seed,
            "decoded": decoded,
            "printable_ratio": p,
            "length": len(decoded),
            "hex": pool[h_index - 1]["stage2_hex"][:20],
            "match_distance": 0,
            "verified": True,
        }

    # Print summary
    good = sum(1 for r in results.values() if r["printable_ratio"] >= 0.8)
    ok = sum(1 for r in results.values() if 0.4 <= r["printable_ratio"] < 0.8)
    bad = sum(1 for r in results.values() if r["printable_ratio"] < 0.4)

    print(f"\n=== Decode Results ===")
    print(f"Total decoded: {len(results)}")
    print(f"Fully decoded (>=80% printable): {good}")
    print(f"Partially decoded (40-80%): {ok}")
    print(f"Failed (<40%): {bad}")

    # Show some fully decoded samples
    print(f"\n=== Sample Decoded Strings (printable >= 0.9) ===")
    samples = [(k, v) for k, v in results.items() if v["printable_ratio"] >= 0.9]
    samples.sort(key=lambda x: x[0])
    for h_idx, r in samples[:30]:
        display = r["decoded"][:60]
        if len(r["decoded"]) > 60:
            display += "..."
        print(f'  H[{h_idx}] seed={r["seed"]} "{display}"')

    # Show some failed examples for debugging
    print(f"\n=== Failed Decodes (printable < 0.3) ===")
    failed = [(k, v) for k, v in results.items() if v["printable_ratio"] < 0.3]
    failed.sort(key=lambda x: x[0])
    for h_idx, r in failed[:10]:
        display = "".join(
            c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in r["decoded"][:40]
        )
        print(f'  H[{h_idx}] seed={r["seed"]} dist={r["match_distance"]} "{display}"')

    # Save results
    output = {}
    for h_idx, r in sorted(results.items()):
        output[str(h_idx)] = {
            "seed": r["seed"],
            "decoded": r["decoded"],
            "printable_ratio": r["printable_ratio"],
            "length": r["length"],
        }

    out_path = BASE / "artifacts" / "decoded_hidden_strings_v2.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
