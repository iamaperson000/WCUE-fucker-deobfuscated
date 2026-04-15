# Phase Six: Decoder Breakthrough

This pass resolved the contradiction from Phase Five by discovering that the byte table shuffle is irrelevant (it maps `x -> string.char(x-1)`, which is identity), and the real obstacle was two missing pieces in the PRNG-derived byte stream:

## The Missing Pieces

### 1. Chained Running Offset

The decode formula is NOT `(byte + rand + 101) % 256` applied independently per byte.

It is a **chained** transform:
```
decoded_byte[i] = (blob_byte[i] + random_byte[i] + running_offset[i]) % 256
running_offset[i+1] = decoded_byte[i]   ← the previous decoded byte becomes the next offset
running_offset[0] = 101
```

This was confirmed by VM trace at line 4502 where `n = 101` is the initial running offset, and then `running_offset` is updated to each decoded byte after use.

### 2. 32-bit Right Rotation in PRNG Refill

The four-byte queue extraction from the PRNG state uses a **double-shift + 32-bit right rotation**:

```
shift1 = 13 - floor(state257 / 32)
T = floor(state45 / 2^shift1)
R = T mod 2^32                          ← take low 32 bits
shift2 = state257 mod 32
rotated = ROR32(R, shift2)              ← 32-bit right rotation
byte0 = rotated AND 0xFF
byte1 = (rotated >> 8) AND 0xFF
byte2 = (rotated >> 16) AND 0xFF
byte3 = (rotated >> 24) AND 0xFF
queue = [byte0, byte1, byte2, byte3]    ← popped LIFO (from end)
```

### 3. Complete PRNG Algorithm

```
state45 = seed % 2^45
state257 = (seed % 255) + 2
running_offset = 101

for each byte in blob:
    if queue empty:
        loop:
            state45 = (state45 * 177 + 5746771741299) % 2^45
            state257 = (state257 * 80) % 257
            if state257 == 1: continue   ← skip invalid state
            break
        shift1 = 13 - floor(state257 / 32)
        T = floor(state45 / 2^shift1)
        R = T mod 2^32
        shift2 = state257 mod 32
        rotated = ROR32(R, shift2)
        queue = [rotated & 0xFF, (rotated>>8)&0xFF, (rotated>>16)&0xFF, (rotated>>24)&0xFF]
    
    random_byte = queue.pop()   ← LIFO (table.remove pops from end)
    decoded = (blob_byte + random_byte + running_offset) % 256
    running_offset = decoded
    result += chr(decoded)
```

## Decoded Results

All Phase Four targets now decode cleanly with 100% printable ratio:

| H Index | Seed | Result |
|---------|------|--------|
| 693 | 17652829380636 | HttpService |
| 2704 | 14670855527087 | `https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/blacklist` |
| 2772 | 2496212501642 | Players |
| 3204 | 30916575737916 | UserInputService |
| 4854 | 1186289386024 | TweenService |
| 5619 | 32879211232206 | RbxAnalyticsService |
| 3869 | 11301675111566 | `https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/key` |
| 942 | 3732199540425 | 0xA91F2C |
| 1542 | 3007687984504 | 0x7fa1bc |
| 2271 | 2668542641370 | `https://discord.gg/4rwgNnyj6B` |
| 2811 | 3575791224449 | WCUE_FUCKER_settings.txt |
| 3615 | 19901264536627 | BindableEvent |
| 5641 | 14043772639627 | WCUE fucker |
| 5897 | 33213205888106 | /settings |
| 6860 | 2711126017262 | /color-presets |

## Script Identity

The obfuscated script is **"WCUE fucker"** — a Roblox exploit script for the game "WCUE" (Whatever Candle Unit Evolution or similar). It:

- Loads remote code from `microwaveyd/WCUE-fucker` on GitHub
- Has a Discord invite: `discord.gg/4rwgNnyj6B`
- Uses services like TweenService, UserInputService, HttpService, RbxAnalyticsService
- Constructs a GUI with color presets
- Includes anti-tamper detection
- Uses `BindableEvent`, `Instance.new`, `Color3`, etc.
- Reads/writes local files like `WCUE_FUCKER_settings.txt`

## Next Steps

Bulk-decode all remaining hidden strings in the dispatcher to produce a fully annotated deobfuscation.