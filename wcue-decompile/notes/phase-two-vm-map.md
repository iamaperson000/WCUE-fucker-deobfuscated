# Phase Two VM Map

## Wrapper Assignment

The first top-level assignment after the decoded string pool splits into 21 helper expressions under:

- `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/vm_wrappers/`

The summary file is:

- `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/vm_wrappers/summary.txt`

## Recovered Helper Roles

- `J`: bulk decref over a handle list proxy. Walks an array of handle ids and releases each entry from `A`/`W`.
- `R`: retain/proxy builder for captured handle lists.
  - Increments refcounts for each handle id.
  - Returns either `newproxy(true)` or a table with metatable fallbacks.
  - Metatable members recovered:
    - `__index`
    - `__gc`
    - `__len`
- `u`: single-handle decref.
- `f`: allocator for a new handle slot.
  - Increments the global slot counter and sets `A[slot] = 1`.
- `W` and `A`: mutable tables used like:
  - `W[slot] = value`
  - `A[slot] = refcount`
- `Z`, `q`, `U`, `L`, `j`, `Y`, `V`, `T`, `i`, `P`, `g`, `O`, `z`:
  - fixed-arity or vararg wrapper factories around the main dispatcher `a`
  - pattern:
    - build retained upvalue proxy via `R(I)`
    - return a Lua closure that calls dispatcher `a(entry_state, args_table, capture_list, capture_proxy)`
- `T` is the vararg entry wrapper used by the outer return:
  - `return (T(...))(X(B))`

## Behavioral Findings

The dispatcher uses recovered runtime-facing strings that strongly indicate a Roblox exploit/executor host:

- Environment and exploit APIs:
  - `getgenv`
  - `gethui`
  - `setclipboard`
  - `toclipboard`
  - `request`
  - `readfile`
  - `writefile`
  - `makefolder`
  - `syn`
- Roblox object model and engine APIs:
  - `Instance`
  - `Enum`
  - `Color3`
  - `CFrame`
  - `workspace`
  - `game`
  - `GetService`
  - `FindFirstChild`
  - `WaitForChild`
  - `GetPlayers`
  - `GetMouse`
  - `GetMouseLocation`
  - `Raycast`
  - `RaycastParams`
  - `GetPartsInPart`
- UI-related strings:
  - `Caption`
  - `AddTab`
  - `Button`
  - `StopButton`
  - `Clipboard`
  - `SetCore`
- Anti-tamper:
  - `Tamper Detected!`

## Loader Evidence

One high-signal branch clearly performs a remote loader flow:

- resolves `game`
- resolves `loadstring`
- resolves `HttpGet`
- executes `loadstring(game:HttpGet(...))`
- then touches `getgenv`

This means the local blob is at least partly a bootstrapper for additional remote code, not a self-contained payload.

## Current Best Read

The hidden runtime is very likely not just “Lua” but a Roblox executor-style environment with exploit APIs available. The script appears to:

- build or manage a custom UI
- adapt to executor capabilities
- load remote code
- enforce an anti-tamper branch

## Next High-Value Step

The hardest unresolved part is the runtime string/key decryption used around raw `H[...]` byte blobs. The next decompilation pass should focus on:

1. identifying the handle-backed helper functions used in the `HttpGet` branch
2. replaying those helper calls offline to recover the actual URL / service names / UI labels
