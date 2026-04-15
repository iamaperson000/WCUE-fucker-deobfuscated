# Phase Four: Loader Trace

This pass stayed strictly inside the derived workspace and avoided the original puzzle files.

## Safe parser note

The first attempt at a generic branch extractor used a regex-heavy splitter and spiked memory on the large dispatcher line. That script has been rewritten to use a linear, line-local parser instead. The safe outputs now live under:

- `artifacts/branch_traces/loader_bootstrap_pretty.lua`
- `artifacts/branch_traces/loader_bootstrap_trace.txt`
- `artifacts/branch_traces/loader_bootstrap_lookups.txt`
- `artifacts/branch_traces/loader_small_pretty.lua`
- `artifacts/branch_traces/loader_small_trace.txt`
- `artifacts/branch_traces/loader_small_lookups.txt`

## Loader bootstrap branch

The large bootstrap branch is anchored at `helper_21_a.lua:5796`.

High-confidence structure:

1. It builds a proxy/metatable pair with:
   - `__index`
   - `__metatable`
   - `setmetatable`

   More specifically, this branch does not appear to use a plain lookup table for `W[b]`. It creates a proxy object via `setmetatable(D, {__index = k, __metatable = nil})` and then stores that proxy in `W[b]`. That makes the repeated access pattern:

   - `key = W[J](blob, seed)`
   - `value = W[b][key]`

   look much more like a lazy decoder/cache than a static constant table.

2. It performs five hidden `game:GetService(...)` calls. The service-name strings are still behind the `W[J]` / `W[b]` decoder pair:
   - `W[b][W[J](H[2772], 2496212501642)]`
   - `W[b][W[J](H[4854], 1186289386024)]`
   - `W[b][W[J](H[3204], 30916575737916)]`
   - `W[b][W[J](H[5619], 32879211232206)]`
   - `W[b][W[J](H[693], 17652829380636)]`

3. It performs a remote code load through:
   - `loadstring(game:HttpGet(W[b][W[J](H[2704], 14670855527087)]))`

4. Immediately after that, it reads one hidden slot from `getgenv()`:
   - `getgenv()[W[b][W[J](H[1542], 3007687984504)]]`

5. It builds a small string cluster from a shared hidden prefix:
   - `prefix = W[b][W[J](H[5641], 14043772639627)]`
   - `prefix .. W[b][W[J](H[5897], 33213205888106)]`
   - `prefix .. W[b][W[J](H[6860], 2711126017262)]`
   - `W[b][W[J](H[2811], 3575791224449)]`
   - `W[b][W[J](H[106], 2711126017262)]`

6. Later in the same branch it transitions into UI/theme construction:
   - repeated `Color3` lookups
   - several numeric color/vector constants
   - later helper creation around `readfile` and `randomString`

Interpretation:

- This is not just a one-shot `HttpGet` bootstrap. It looks like a staged loader with:
  - service acquisition
  - metatable/proxy setup
  - remote fetch/execute
  - `getgenv` handoff
  - cached or derived string construction
  - UI/theme setup
  - executor/file compatibility helpers

## Smaller loader branch

The compact branch is anchored at `helper_21_a.lua:4001`.

High-confidence structure:

1. It performs a direct:
   - `loadstring(game:HttpGet(W[b][W[J](H[3869], 11301675111566)]))`

2. It then touches `getgenv()` via:
   - `W[b][W[J](H[942], 3732199540425)]`

3. One hidden string in this smaller branch is very likely already identifiable:
   - `W[b][W[J](H[2271], 2668542641370)]` is most likely `"new"`

Why this is a strong guess:

- The resulting value is used as `Instance[decoded_name]`, and then immediately called with another decoded string:
  - `Instance[decoded_name](decoded_arg)`
- In Roblox/Lua executor code, that pattern is overwhelmingly `Instance.new(className)`.

4. The next hidden string in that sequence is therefore likely a class name:
   - `W[b][W[J](H[3615], 19901264536627)]`

## What is still unresolved

These are the best next targets for actual deobfuscation:

- the five hidden `GetService` names in the bootstrap branch
- the hidden URL/name behind `H[2704]`
- the hidden URL/name behind `H[3869]`
- the hidden `getgenv` slot names behind `H[1542]` and `H[942]`
- the prefix/suffix string cluster behind `H[5641]`, `H[5897]`, `H[6860]`, `H[2811]`, and `H[106]`

## Recommended next move

The next practical solve step is to recover the `W[J]` / `W[b]` decoder pair itself rather than guess individual strings. At this point we have enough concrete call sites to recognize that pair by behavior:

- `W[J](blob, seed)` computes a lookup key
- `W[b][key]` returns the real string/value

If we can identify where that table/function pair is initialized, the remaining hidden service names and URL pieces should collapse quickly.
