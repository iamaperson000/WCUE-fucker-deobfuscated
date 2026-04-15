# First Pass Findings

## Safety

- Original puzzle files were left untouched:
  - `/Users/kanishkv/Developer/wcue deobf/source`
  - `/Users/kanishkv/Developer/wcue deobf/source.lua`
- All reverse-engineering work lives under `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/`.

## Decoding Pipeline

1. The `H` table in `source.lua` contains 7,100 Lua string literals encoded with decimal escapes.
2. After unescaping, 7,099 entries are base64-shaped strings.
3. The blob then performs an in-place permutation on `H` with swap ranges:
   - `(1, 7100)`
   - `(1, 964)`
   - `(965, 7100)`
4. The blob decodes every string entry using a custom base64 alphabet:
   - `I/H1RtQ4mZAT78B3sdo0LbNV+MCKwhzvaS6qJyGPDeOuknWpglEjiFrXfc29x5UY`
5. After that second pass, `H` contains the actual runtime-facing string pool used by `I(expr)` lookups, where:
   - `I(n)` resolves to `H[n + 20314]`

## Evidence Recovered

- Confirmed decoded lookup:
  - `table[I(-738701+722915)]` resolves to `table["unpack"]`
- High-signal recovered names include:
  - `Instance`
  - `Enum`
  - `Color3`
  - `math`
  - `Connect`
  - `getgenv`
  - `game`
  - `task`
  - `IsA`
  - `ipairs`
  - `FindFirstChild`
  - `GetService`
  - `Destroy`
  - `WaitForChild`
  - `string`
  - `setclipboard`
  - `toclipboard`
  - `loadstring`
  - `gethui`
  - `SetCore`
  - `request`
  - `readfile`
  - `writefile`
  - `makefolder`
  - `syn`
  - `http`

## Current Read

- This is not just generic obfuscation; it is a VM-style protected script with a real decoded string pool.
- The decoded pool strongly suggests a Roblox/executor-style host environment:
  - object model names like `Instance`, `Color3`, `CFrame`
  - exploit-facing names like `getgenv`, `gethui`, `setclipboard`, `toclipboard`, `request`, `syn`
  - file and HTTP helpers like `readfile`, `writefile`, `makefolder`, `HttpGet`
- The next highest-value step is to keep annotating execution helpers and recover the VM opcodes / wrapper functions around the dispatcher.

## Artifacts

- Stage 1 pool dump:
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool.json`
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool.txt`
- Stage 2 pool dump:
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool_stage2.json`
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool_stage2.txt`
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool_meta.json`
- `I(...)` annotation artifacts:
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/source_i_annotated.lua`
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/used_i_lookups.json`
  - `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/used_i_lookups.txt`
