# Phase Seven: Full Deobfuscation — Complete

## Final Results

| Metric | Count | Percentage |
|--------|-------|------------|
| Total H entries | 7,100 | 100% |
| Hex-encoded strings | ~6,300 | ~89% |
| Named (plaintext) strings | ~460 | ~6% |
| **CONFIDENT decodes** (>=95% printable) | **5,792** | **82%** |
| LIKELY decodes (85-95% printable) | 207 | 3% |
| UNCERTAIN decodes (40-85% printable) | 167 | 2% |
| Named string annotations | 3,305 | — |
| **Total annotations in source** | **9,497** | — |

## String Decoder Algorithm (Confirmed)

```
state45 = seed % 2^45
state257 = (seed % 255) + 2
running_offset = 101
queue = []

for byte in blob:
    if queue empty:
        loop:
            state45 = (state45 * 177 + 5746771741299) % 2^45
            state257 = (state257 * 80) % 257
            if state257 == 1: continue
            shift1 = max(13 - (state257 // 32), 0)
            T = state45 >> shift1
            R = T & 0xFFFFFFFF
            shift2 = state257 % 32
            rotated = ROR32(R, shift2)
            queue = [rotated & 0xFF, (rotated>>8)&0xFF, (rotated>>16)&0xFF, (rotated>>24)&0xFF]
            break
    random_byte = queue.pop()  // LIFO
    decoded = (byte + random_byte + running_offset) % 256
    running_offset = decoded    // chain: prev decoded byte becomes next offset
```

## Key Decoded Strings

### URLs & Endpoints
- `https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/blacklist`
- `https://raw.githubusercontent.com/microwaveyd/WCUE-fucker/main/key`
- `https://discord.gg/4rwgNnyj6B`
- `https://discord.gg/PK8fkPb8zX`
- `https://discord.com/api/webhooks/1486021216161628190/fmZSzOHNJ4fKM2GidyxwZaJ9fu1MiPRFtHdwq6EyuN_m-VGxGsL4Lx4uUY-FGtm6LDq6`
- `https://wcuefucker.microwaveyd.workers.dev/`

### Roblox Services & APIs
- HttpService, TweenService, UserInputService, Players, RunService
- RbxAnalyticsService, GuiService
- Instance, Color3, UDim2, Enum, CFrame, Vector3

### Script Features
- **Color manipulation**: Color Finder, Near Color Finder, Random Color Finder, Color Presets, Apply Color
- **Physics**: Physics Fucker mode
- **Anti-tamper**: Blacklist check, key verification, whitelisting via hex identifiers (0x7fa1bc, 0xA91F2C)
- **File I/O**: WCUE_FUCKER_settings.txt, WCUE_FUCKER_color_presets.txt
- **Discord integration**: Link copying, webhook logging, key fetching

### GUI Labels
- "WCUE Fucker ;3", "WCUE fucker", "Tutorial on Discord", "Tutorial on discord :3"
- "Enter key", "Get Key (Discord)", "Blacklist", "Preset Colors"
- "color finder", "color picker", "colorFX", "color presets"
- "Physics Fucker", "Near Color Finder", "Random Color Finder"

## Pipeline Stages

### Stage 1: H Table Extraction
- Extracted 7,100 Lua string literals with decimal escape sequences
- Custom base64 decoding using alphabet: `I/H1RtQ4mZAT78B3sdo0LbNV+MCKwhzvaS6qJyGPDeOuknWpglEjiFrXfc29x5UY`

### Stage 2: String Pool Permutation
- Swap-range reordering applied to H table entries
- Ranges: (1,7100), (1,964), (965,7100)

### Stage 3: VM Architecture Mapping
- 21 helper wrappers around dispatcher function `a`
- Refcounting: J (decref), R (retain/builder), u (single decref), f (new slot)
- W/A tables: mutable value/refcount storage
- Handle/proxy system forManagedObject references

### Stage 4: Decoder Shape Analysis
- Identified W[J] decoder pattern: `W[blob_index](blob, seed)`
- PRNG-based decryption with LCG states

### Stage 5: Seed Extraction
- Regex-based extraction from dispatcher bytecode
- Arithmetic evaluation for obfuscated seed computation
- Nested parenthesis support for expressions like `32787479085778-(-30929)`

### Stage 6: Decoder Breakthrough
- Discovered chained running offset (initial=101)
- Discovered 32-bit right rotation in PRNG refill
- Verified all Phase Four test targets decode correctly

### Stage 7: Full Deobfuscation
- Bulk decoding of 6,166 strings with 97.3% CONFIDENT/LIKELY accuracy
- Brute-force seed matching for uncertain entries
- Annotated source (9,497 replacements)
- Comprehensive string catalog

## Files

| File | Description |
|------|-------------|
| `artifacts/source_deobfuscated.lua` | Full source with decoded string replacements (1.66M chars) |
| `artifacts/vm_wrappers/helper_21_a_annotated.lua` | Annotated dispatcher |
| `artifacts/decoded_strings_lookup.json` | Decoded strings lookup (6,166 entries) |
| `artifacts/decoded_hidden_strings_v3.json` | Raw decode results |
| `artifacts/string_pool_stage2.json` | Stage 2 string pool |
| `scripts/bulk_decode_v3.py` | Bulk decoder (nested-paren regex) |
| `scripts/brute_force_seeds.py` | Brute-force seed matching |
| `scripts/annotate_dispatcher.py` | Dispatcher annotation |
| `scripts/annotate_full_source.py` | Source annotation |
| `scripts/decode_strings.py` | Single-string decoder |
| `scripts/extract_string_pool.py` | H table extraction |
| `notes/phase-seven-deobfuscation.md` | This document |

## Final Decode Statistics

| Metric | Count | Percentage |
|--------|-------|------------|
| Total H entries | 7,100 | 100% |
| Hex-encoded (needs decoding) | ~6,300 | ~89% |
| Named (plaintext) | ~460 | ~6% |
| **CONFIDENT decodes** (>=95% printable) | **5,948** | **96.5%** |
| LIKELY decodes (85-95%) | 212 | 3.4% |
| UNCERTAIN (<85%) | 6 | 0.1% |
| **TOTAL resolved** | **6,160** | **99.90%** |
| Named string annotations | 3,305 | — |
| **Total annotations in source** | **9,497** | — |

### Remaining 6 Uncertain Entries

These have seeds computed through VM table indirection (e.g., `seed = W[v[N]]` where the value was stored by a prior dispatch state). Cannot be resolved by static analysis — requires full VM execution tracing.

| H Index | Printable | Likely String |
|---------|-----------|---------------|
| 139 | 0.82 | Unknown (22 bytes) |
| 544 | 0.81 | Unknown (16 bytes) |
| 799 | 0.81 | Unknown (16 bytes) |
| 3180 | 0.82 | Unknown (22 bytes) |
| 3972 | 0.76 | Unknown (17 bytes) |
| 4195 | 0.82 | Unknown (22 bytes) |

## Remaining Work

1. **6 UNCERTAIN entries**: Seeds computed through indirect VM operations (W/v table lookups). Would require full VM state tracing to resolve.
2. **VM dispatcher deobfuscation**: Replace binary-search state comparisons (`a<N`, `a>=M`) with symbolic labels and add semantic annotations for each dispatch state.
3. **Pseudocode generation**: Convert VM operations to readable Lua pseudocode, revealing the script's actual logic.
4. **Security analysis**: Document exploit mechanisms, anti-tamper checks, and lateral movement paths.