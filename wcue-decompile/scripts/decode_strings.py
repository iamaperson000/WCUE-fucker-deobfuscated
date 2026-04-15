#!/usr/bin/env python3
"""
WCUE String Decoder - Final Implementation

Algorithm discovered through VM reverse engineering:

1. Initialize PRNG:
   - state45 = seed % 2^45
   - state257 = (seed % 255) + 2
   - running_offset = 101

2. For each byte in blob:
   a. If queue empty, refill:
      - state45 = (state45 * 177 + 5746771741299) % 2^45
      - state257 = (state257 * 80) % 257
      - If state257 == 1: skip and re-roll (update state45 again)
      - shift1 = 13 - (state257 // 32)
      - T = floor(state45 / 2^shift1)
      - R = T % 2^32  (lower 32 bits)
      - shift2 = state257 % 32
      - rotated = ROR32(R, shift2) = ((R >> shift2) | (R << (32 - shift2))) & 0xFFFFFFFF
      - byte0 = rotated & 0xFF
      - byte1 = (rotated >> 8) & 0xFF
      - byte2 = (rotated >> 16) & 0xFF
      - byte3 = (rotated >> 24) & 0xFF
      - queue = [byte0, byte1, byte2, byte3]
   b. Pop from queue (LIFO - table.remove pops from end): random_byte = queue.pop()
   c. decoded_byte = (blob_byte + random_byte + running_offset) % 256
   d. running_offset = decoded_byte  (chain: previous decoded becomes next offset)
   e. result += chr(decoded_byte)

3. Result is the decoded string
"""

import json
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
    """32-bit right rotation."""
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
            # Refill from PRNG
            while True:
                state45 = (state45 * 177 + 5746771741299) % (2**45)
                state257 = (state257 * 80) % 257
                if state257 == 1:
                    # Skip: re-roll state45
                    continue

                # Extract 4 bytes using double-shift + rotation
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

        # Pop from end (LIFO, matching Lua table.remove behavior)
        random_byte = queue.pop()

        # Decode: chained XOR/add with running offset
        decoded = (byte_val + random_byte + running_offset) % 256
        running_offset = decoded  # Chain: previous decoded byte becomes offset
        result.append(chr(decoded))

    return "".join(result)


def main():
    pool = load_stage2_pool()
    print(f"Loaded {len(pool)} stage-2 entries")

    # Known test targets from Phase Four
    targets = {
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

    # Also decode known plaintext H entries to verify
    # From Phase One, we know I(expr) resolves to known strings like:
    # I(-738701+722915) should give "unpack"
    # etc. Let me also test with blobs that should decode to known strings.

    print("\n=== Known Target Decodes ===")
    print(f"{'H[idx]':<10} {'seed':<20} {'len':<5} {'result'}")
    print("-" * 80)

    for h_idx in sorted(targets.keys()):
        seed = targets[h_idx]
        blob = get_blob(pool, h_idx)
        if blob is None:
            print(f"H[{h_idx}]{'':<5} {seed:<20} {'N/A':<5} BLOB NOT FOUND")
            continue

        result = decode_blob(blob, seed)
        printable = sum(1 for c in result if 32 <= ord(c) < 127 or c in "\t\n\r") / max(
            len(result), 1
        )

        # Show printable representation
        display = "".join(
            c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in result[:80]
        )
        if len(result) > 80:
            display += "..."

        print(
            f'H[{h_idx}]{"":<5} {seed:<20} {len(blob):<5} printable={printable:.2f} "{display}"'
        )

    # Now bulk-decode ALL hidden strings (ones not already decoded in stage 2)
    # These are entries marked as "hex:..." in the I() annotations
    print("\n\n=== Bulk Decoding All Hidden Strings ===")
    print(f"{'H[idx]':<10} {'seed':<20} {'len':<5} {'result'}")

    # Collect all (H_index, seed) pairs from the dispatcher annotations
    # We need to re-scan the dispatcher for W[J](H[...], ...) patterns
    import re

    dispatcher = (BASE / "artifacts/vm_wrappers/helper_21_a.lua").read_text()

    # Find all W[J](H[idx], seed) patterns, which are actually like:
    # d(H[idx], seed) or F(H[idx], seed) etc - the variable names vary
    # But we know the pattern is: decoder_closure(blob, seed)
    # The blob is always H[something] and the seed is a large number

    # Actually, let's find ALL I() references with H annotations and extract
    # the ones that are "hex:..." (i.e., not yet decoded)

    # For now, let's decode the specific targets from Phase Four more thoroughly
    # and also do a wider scan

    decoded_count = 0
    for h_idx, seed in sorted(targets.items()):
        blob = get_blob(pool, h_idx)
        if blob is None:
            continue
        result = decode_blob(blob, seed)
        printable = sum(1 for c in result if 32 <= ord(c) < 127) / max(len(result), 1)
        if printable > 0.5:
            decoded_count += 1


if __name__ == "__main__":
    main()
