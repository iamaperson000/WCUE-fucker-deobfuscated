#!/usr/bin/env python3
"""
Brute-force seed matching for uncertain/failed decoded entries.

For each H index with printable_ratio < 0.85, try ALL seed candidates
from the file and keep the best result.
"""

import json
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


def load_seed_candidates():
    """Load all unique seed values from the decoded strings."""
    with open(BASE / "artifacts/decoded_hidden_strings_v3.json") as f:
        data = json.load(f)
    seeds = set()
    for v in data.values():
        seeds.add(v["seed"])
    return sorted(seeds)


def main():
    pool = load_stage2_pool()

    with open(BASE / "artifacts/decoded_strings_lookup.json") as f:
        lookup = json.load(f)

    # Load all seed candidates
    all_seeds = load_seed_candidates()
    print(f"Loaded {len(all_seeds)} unique seed candidates")

    # Find entries needing improvement
    needs_improvement = {}
    for k, v in lookup.items():
        if v["confidence"] == "UNCERTAIN":
            needs_improvement[int(k)] = v

    print(f"Entries needing improvement: {len(needs_improvement)}")

    improved = 0
    still_uncertain = 0
    made_worse = 0

    for h_index in sorted(needs_improvement.keys()):
        old_info = needs_improvement[h_index]
        old_pr = old_info["printable_ratio"]
        blob = get_blob(pool, h_index)
        if blob is None:
            still_uncertain += 1
            continue

        best_decoded = old_info["string"]
        best_pr = old_pr
        best_seed = old_info["seed"]

        # For short strings, require 100% printable to accept
        # For longer strings, require >= 0.95
        min_acceptable_pr = 0.95 if len(blob) > 5 else 1.0

        for seed in all_seeds:
            try:
                decoded = decode_blob(blob, seed)
                pr = printable_ratio(decoded)
                if pr > best_pr:
                    best_decoded = decoded
                    best_pr = pr
                    best_seed = seed
                    if pr >= min_acceptable_pr:
                        break
            except:
                continue

        if best_pr > old_pr + 0.05:
            # Improved!
            lookup[str(h_index)] = {
                "string": best_decoded,
                "printable_ratio": best_pr,
                "seed": best_seed,
                "confidence": "CONFIDENT"
                if best_pr >= 0.95
                else "LIKELY"
                if best_pr >= 0.85
                else "UNCERTAIN",
                "length": len(best_decoded),
            }
            improved += 1
        elif best_pr >= old_pr:
            still_uncertain += 1
        else:
            made_worse += 1

        if improved % 100 == 0 and improved > 0:
            print(
                f"  Progress: {improved} improved, {still_uncertain} unchanged, {made_worse} worse out of {improved + still_uncertain + made_worse}"
            )

    print(
        f"\nFinal: {improved} improved, {still_uncertain} unchanged, {made_worse} worse"
    )

    # Save updated lookup
    with open(BASE / "artifacts/decoded_strings_lookup.json", "w") as f:
        json.dump(lookup, f, indent=2, ensure_ascii=False)
    print("Saved updated lookup")

    # Save updated v3 results
    with open(BASE / "artifacts/decoded_hidden_strings_v3.json") as f:
        v3_data = json.load(f)

    for k, v in lookup.items():
        if k in v3_data:
            v3_data[k]["decoded"] = v["string"]
            v3_data[k]["printable_ratio"] = v["printable_ratio"]
            v3_data[k]["seed"] = v["seed"]

    with open(BASE / "artifacts/decoded_hidden_strings_v3.json", "w") as f:
        json.dump(v3_data, f, indent=2, ensure_ascii=False)
    print("Saved updated v3 results")

    # Print summary
    conf = sum(1 for v in lookup.values() if v["confidence"] == "CONFIDENT")
    like = sum(1 for v in lookup.values() if v["confidence"] == "LIKELY")
    unce = sum(1 for v in lookup.values() if v["confidence"] == "UNCERTAIN")
    print(f"\nUpdated stats: CONFIDENT={conf}, LIKELY={like}, UNCERTAIN={unce}")


if __name__ == "__main__":
    main()
