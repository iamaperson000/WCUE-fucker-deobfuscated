#!/usr/bin/env python3
"""
Targeted seed extraction for uncertain entries.

For each uncertain H index:
1. Find the I() call in the dispatcher
2. In the surrounding context, find the decoder call pattern: func(blob_var, seed_var)
3. Trace back to find the seed_var's assignment and evaluate the arithmetic
4. Try all extracted seeds against the blob
"""

import json
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


def eval_arith(expr):
    """Safely evaluate arithmetic expressions like '12345-6789' or '12345-(-6789)'."""
    expr = expr.strip().replace(" ", "")
    try:
        val = int(eval(expr))
        if not isinstance(val, int) or abs(val) > 10**15:
            return None
        return val
    except:
        return None


def extract_seeds_from_context(context_text):
    """Extract ALL arithmetic seed values from a context string."""
    seeds = []
    # Match two-operand arithmetic: number op number or number op (number) or number op (-number)
    # Also bare large numbers

    # Pattern for compound: DIGIT+ op (DIGIT+) or DIGIT+ op DIGIT+ or DIGIT+ op -DIGIT+
    # Handles: 12345-6789, 12345+6789, 12345-(-6789), -825091+28937375910822
    compound_pattern = re.compile(
        r"(-?\d{4,14})"  # First operand (4+ digits to avoid noise)
        r"([+\-])"  # Operator
        r"\(?"  # Optional opening paren
        r"(-?\d{1,14})"  # Second operand
        r"\)?"  # Optional closing paren
    )

    for m in compound_pattern.finditer(context_text):
        try:
            val1 = int(m.group(1))
            op = m.group(2)
            val2_raw = m.group(3)
            # Handle the parenthesis case: 12345-(-6789) means 12345-(-6789) = 12345+6789
            # In regex, group(3) includes the minus if present

            # We need to check if there's a ( before the second number
            full_match = m.group(0)
            # Re-evaluate the full expression
            full_val = int(eval(full_match.replace(" ", "")))

            if 1_000_000 <= abs(full_val) <= 99_999_999_999_999:
                seeds.append(full_val)
        except:
            pass

    # Also bare large numbers (10+ digits, not part of compound expressions)
    bare_pattern = re.compile(r"(?<![0-9a-fA-Fx\-])(\d{10,14})(?![0-9a-fA-Fx])")
    for m in bare_pattern.finditer(context_text):
        val = int(m.group(1))
        if 1_000_000_000 <= val <= 99_999_999_999_999:
            seeds.append(val)

    return list(set(seeds))


def main():
    pool = load_stage2_pool()

    with open(BASE / "artifacts/decoded_strings_lookup.json") as f:
        lookup = json.load(f)

    uncertain_indices = set(
        int(k) for k, v in lookup.items() if v["confidence"] == "UNCERTAIN"
    )
    print(f"Uncertain H indices: {len(uncertain_indices)}")

    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()

    # For each uncertain H index, find ALL references in the dispatcher
    # and extract seeds from a wide context around each reference
    improved = 0
    still_uncertain = 0

    for h_idx in sorted(uncertain_indices):
        blob = get_blob(pool, h_idx)
        if blob is None:
            still_uncertain += 1
            continue

        old_info = lookup[str(h_idx)]
        old_pr = old_info["printable_ratio"]
        old_seed = old_info["seed"]

        # Find the hex reference for this H index
        hex_pattern = re.compile(
            rf"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[{h_idx}\]=hex:([0-9a-fA-F]+)\]\]"
        )

        best_decoded = old_info["string"]
        best_pr = old_pr
        best_seed = old_seed

        # Also try ALL seeds from a very wide context around each reference
        for m in hex_pattern.finditer(dispatcher):
            pos = m.start()
            # Extract seeds from a wide context (2000 chars each side)
            start = max(0, pos - 2000)
            end = min(len(dispatcher), pos + 2000)
            context = dispatcher[start:end]

            seeds_in_context = extract_seeds_from_context(context)

            # Also find seeds that look like they're assigned to a variable
            # Pattern: VAR = arithmetic  followed eventually by decoder_call(VAR, ...)
            # The variable names for seeds in VM context are typically short single/double letters

            for seed in seeds_in_context:
                if seed == best_seed:
                    continue  # Already tried
                try:
                    decoded = decode_blob(blob, seed)
                    if decoded is None:
                        continue
                    pr = printable_ratio(decoded)
                    if pr > best_pr + 0.02:
                        best_pr = pr
                        best_decoded = decoded
                        best_seed = seed
                        if pr >= 0.95:
                            break
                except:
                    continue

            if best_pr >= 0.95:
                break

        # Update if improved
        if best_pr > old_pr + 0.02:
            confidence = (
                "CONFIDENT"
                if best_pr >= 0.95
                else "LIKELY"
                if best_pr >= 0.85
                else "UNCERTAIN"
            )
            lookup[str(h_idx)] = {
                "string": best_decoded,
                "printable_ratio": best_pr,
                "seed": best_seed,
                "confidence": confidence,
                "length": len(best_decoded),
            }
            improved += 1
            if best_pr >= 0.85:
                print(
                    f'  H[{h_idx}] IMPROVED: {old_pr:.2f} -> {best_pr:.2f} seed={best_seed} "{best_decoded[:40]}"'
                )
        else:
            still_uncertain += 1

    print(f"\nImproved: {improved}, Still uncertain: {still_uncertain}")

    # Summary
    conf = sum(1 for v in lookup.values() if v["confidence"] == "CONFIDENT")
    like = sum(1 for v in lookup.values() if v["confidence"] == "LIKELY")
    unce = sum(1 for v in lookup.values() if v["confidence"] == "UNCERTAIN")
    print(f"Updated stats: CONFIDENT={conf}, LIKELY={like}, UNCERTAIN={unce}")

    # Save updated lookup
    with open(BASE / "artifacts/decoded_strings_lookup.json", "w") as f:
        json.dump(lookup, f, indent=2, ensure_ascii=False)

    # Also update v3 results
    with open(BASE / "artifacts/decoded_hidden_strings_v3.json") as f:
        v3_data = json.load(f)

    for k, v in lookup.items():
        if k in v3_data:
            v3_data[k]["decoded"] = v["string"]
            v3_data[k]["printable_ratio"] = v["printable_ratio"]
            v3_data[k]["seed"] = v["seed"]

    with open(BASE / "artifacts/decoded_hidden_strings_v3.json", "w") as f:
        json.dump(v3_data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
