# Phase Three Behavior Anchors

## Key Dispatcher Anchors

These references point into:

- `/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/vm_wrappers/helper_21_a.lua`

## Anti-Tamper

- Around line 3088 the dispatcher explicitly calls `error("Tamper Detected!")`.
- This is a direct intact string, not a heuristic guess.

## UI Construction

- Around line 3395 there is a clear UI-oriented branch that uses:
  - `Caption`
  - `AddTab`
  - `Button`
  - `StopButton`
  - `Instance`
  - `UDim2`
  - `Color3`
- That branch also allocates many handles and writes multiple properties, which strongly suggests it is constructing a live GUI tree rather than just naming abstract callbacks.

## Remote Loader Path 1

- Around line 4001 there is a direct bootstrap sequence:
  - resolve `game`
  - resolve `loadstring`
  - resolve `HttpGet`
  - call `loadstring(game:HttpGet(...))`
  - then touch `getgenv`
  - then create `Instance` objects and assign a number of properties
- This looks like a classic remote script bootstrap plus environment registration.

## Remote Loader Path 2

- Around line 5796 there is a second loader branch that also includes:
  - `__index`
  - `__metatable`
  - `setmetatable`
  - `task`
  - `game`
  - `GetService`
  - `loadstring`
  - `HttpGet`
  - `getgenv`
  - `readfile`
  - `randomString`
  - `pcall`
  - `Connect`
- This branch appears more elaborate than the first and likely builds a cached/bootstrap context around remote loading.

## Runtime Detection / Compatibility

- The dispatcher contains capability checks or compatibility branches around:
  - `syn`
  - `request`
  - `gethui`
  - `setclipboard`
  - `toclipboard`
  - `readfile`
  - `writefile`
  - `makefolder`
- This strongly supports the “executor compatibility layer” reading rather than a normal game-side LocalScript.

## Best Current Interpretation

At this point the puzzle blob looks like:

1. a VM-protected Roblox executor bootstrapper
2. with GUI construction
3. anti-tamper behavior
4. at least two remote-code loader branches
5. extra compatibility logic for executor APIs and local file IO

## Next Decompilation Target

The next high-value target is the small family of runtime helper handles used to decode raw `H[...]` byte blobs into:

- service names passed into `GetService`
- the `HttpGet` target(s)
- remaining UI/property names that are still raw byte entries
