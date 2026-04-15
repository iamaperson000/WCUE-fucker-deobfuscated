#!/usr/bin/env python3
"""
Ultra-aggressive seed extraction: try ALL arithmetic combinations found in
the entire dispatcher file, including 3-operand expressions and results of
adding/subtracting any two large numbers from the file.
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
    return bytes.fromhex(pool[h_index - 1]["stage2_hex"])


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
                queue = [
                    rotated & 0xFF,
                    (rotated >> 8) & 0xFF,
                    (rotated >> 16) & 0xFF,
                    (rotated >> 24) & 0xFF,
                ]
                break
        random_byte = queue.pop()
        decoded = (byte_val + random_byte + running_offset) % 256
        running_offset = decoded
        result.append(chr(decoded))
    return "".join(result)


def printable_ratio(s):
    if not s:
        return 0.0
    return sum(
        1 for c in s if 32 <= ord(c) < 127 or c in "\t\n\r" or ord(c) > 127
    ) / len(s)


def main():
    pool = load_stage2_pool()

    with open(BASE / "artifacts/decoded_strings_lookup.json") as f:
        lookup = json.load(f)

    uncertain = {k: v for k, v in lookup.items() if v["confidence"] == "UNCERTAIN"}
    print(f"Remaining uncertain entries: {len(uncertain)}")

    # Extract ALL large numbers from dispatcher
    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()

    # Already tried: 13K seeds from simple arithmetic and bare numbers
    # Now try: extract 3-operand expressions
    # Pattern: SMALL + BIG1 - BIG2 or variations
    # Actually, let's try the seeds from decoded string values themselves
    # Some H entries might use other H values as seeds through the I() function

    # First, let's find the contexts around each uncertain entry and extract
    # every possible arithmetic expression within a 3000-char window
    pattern = re.compile(
        rf"I\(([^)]*(?:\([^)]*\))*[^)]*)\)--\[\[H\[(\d+)\]=hex:([0-9a-fA-F]+)\]\]"
    )

    # For each uncertain entry, get very wide context and try EVERY number
    all_seeds = set()
    for m in re.finditer(r"(?<![0-9a-fA-Fx])(\d{8,14})(?![0-9a-fA-Fx])", dispatcher):
        val = int(m.group(1))
        if 100_000 <= val <= 99_999_999_999_999:
            all_seeds.add(val)

    # Also try results of all 2-operand expressions
    for m in re.finditer(r"(-?\d{4,14})\s*([+\-])\s*\(?(-?\d{1,14})\)?", dispatcher):
        try:
            val = int(eval(m.group(0).replace(" ", "")))
            if 1_000_000_000 <= abs(val) <= 99_999_999_999_999:
                all_seeds.add(abs(val))
        except:
            pass

    print(f"Total candidate seeds: {len(all_seeds)}")

    improved = 0
    still_uncertain = 0

    for k, v in uncertain.items():
        h_idx = int(k)
        blob = get_blob(pool, h_idx)
        if blob is None:
            still_uncertain += 1
            continue

        old_pr = v["printable_ratio"]
        best_pr = old_pr
        best_decoded = v["string"]
        best_seed = v["seed"]

        for seed in all_seeds:
            try:
                decoded = decode_blob(blob, seed)
                pr = printable_ratio(decoded)
                if pr > best_pr:
                    best_pr = pr
                    best_decoded = decoded
                    best_seed = seed
                    if pr >= 0.95:
                        break
            except:
                continue

        if best_pr > old_pr + 0.02:
            confidence = (
                "CONFIDENT"
                if best_pr >= 0.95
                else "LIKELY"
                if best_pr >= 0.85
                else "UNCERTAIN"
            )
            lookup[k] = {
                "string": best_decoded,
                "printable_ratio": best_pr,
                "seed": best_seed,
                "confidence": confidence,
            }
            improved += 1
            display = (
                best_decoded[:50]
                if len(best_decoded) <= 50
                else best_decoded[:47] + "..."
            )
            print(
                f'  H[{h_idx}] {old_pr:.2f} -> {best_pr:.2f} seed={best_seed} "{display}" [{confidence}]'
            )
        else:
            still_uncertain += 1

    print(f"\nImproved: {improved}, Still uncertain: {still_uncertain}")

    conf = sum(1 for v in lookup.values() if v["confidence"] == "CONFIDENT")
    like = sum(1 for v in lookup.values() if v["confidence"] == "LIKELY")
    unce = sum(1 for v in lookup.values() if v["confidence"] == "UNCERTAIN")
    print(f"Updated stats: CONFIDENT={conf}, LIKELY={like}, UNCERTAIN={unce}")

    with open(BASE / "artifacts/decoded_strings_lookup.json", "w") as f:
        json.dump(lookup, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
