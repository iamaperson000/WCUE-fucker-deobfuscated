# WCUE Deobfuscation - Phase 6 Decoder Breakthrough Summary

## Status: DECODER COMPLETE

The string decoder has been fully reverse-engineered and verified. All previously hidden strings from Phase Four now decode perfectly with 100% printable ratio.

## Decoder Algorithm

```python
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
                    continue  # Skip invalid state
                
                # Double-shift + 32-bit rotation extraction
                shift1 = 13 - (state257 // 32)
                if shift1 < 0: shift1 = 0
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
        
        random_byte = queue.pop()  # LIFO (table.remove pops from end)
        decoded = (byte_val + random_byte + running_offset) % 256
        running_offset = decoded  # Chain: previous decoded byte becomes offset
        result.append(chr(decoded))
    
    return ''.join(result)
```

## Key Discoveries

The decoder differs from the Phase Five model in two critical ways:

### 1. Chained Running Offset
The constant 101 is only the INITIAL offset. After each byte, the running offset is updated to the just-decoded byte:
- `decoded[i] = (blob[i] + random[i] + offset[i]) % 256`
- `offset[i+1] = decoded[i]`
- `offset[0] = 101`

### 2. Double-Shift + 32-bit Right Rotation
The 4-byte queue extraction is NOT a simple split of a 32-bit value. It uses:
1. A primary shift: `shift1 = 13 - floor(state257 / 32)` 
2. A secondary rotation: `ROR32(lower_32_bits >> shift1, state257 % 32)`
3. The result is split into 4 bytes (little-endian)
4. `table.remove` pops from the END (LIFO), so bytes are consumed in reverse order: byte3, byte2, byte1, byte0

## Verified Decoded Strings

| H Index | Seed | Decoded Value |
|---------|------|---------------|
| 693 | 17652829380636 | **HttpService** |
| 942 | 3732199540425 | **0xA91F2C** (hex color) |
| 1542 | 3007687984504 | **0x7fa1bc** (hex color) |
| 2271 | 2668542641370 | **https://discord.gg/4rwgNnyj6B** |
| 2704 | 14670855527087 | **https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/blacklist** |
| 2772 | 2496212501642 | **Players** |
| 2811 | 3575791224449 | **WCUE_FUCKER_settings.txt** |
| 3204 | 30916575737916 | **UserInputService** |
| 3615 | 19901264536627 | **BindableEvent** |
| 3869 | 11301675111566 | **https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/key** |
| 4854 | 1186289386024 | **TweenService** |
| 5619 | 32879211232206 | **RbxAnalyticsService** |
| 5641 | 14043772639627 | **WCUE fucker** |
| 5897 | 33213205888106 | **/settings** |
| 6860 | 2711126017262 | **/color-presets** |

## Script Identity

**"WCUE fucker"** — a Roblox exploit script targeting the game "WCUE" (Whatever Candle Unit Evolution).
- GitHub org: `microwaveyd/WCUE-fucker`
- Remote code URLs: blacklist and key endpoints on GitHub
- Discord: `discord.gg/4rwgNnyj6B`
- Config file: `WCUE_FUCKER_settings.txt`

## Remaining Work

To decode ALL remaining hidden strings, a proper VM trace is needed to extract every `(H_index, seed)` pair from the dispatcher. The naive regex approach in bulk_decode.py doesn't reliably extract seeds because the VM scatters blob references and seeds across separate instructions.