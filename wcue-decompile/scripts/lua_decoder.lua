#!/usr/bin/env lua
-- WCUE Sandbox Decoder
-- Runs source.lua in a sandbox and captures W[J] decoder outputs
--
-- The source.lua structure:
-- return(function(...) end)(getfenv() or _ENV, unpack or table[...], newproxy, setmetatable, ...)
--
-- We need to intercept at the point where W[J] (the decoder function) is called.

-- Build a sandboxed environment
local captured_strings = {}
local captured_decoder_calls = {}

local sandbox_env = {
    table = table,
    math = math,
    string = string,
    pairs = pairs,
    ipairs = ipairs,
    next = next,
    select = select,
    type = type,
    tonumber = tonumber,
    tostring = tostring,
    error = error,
    pcall = pcall,
    rawset = rawset,
    rawget = rawget,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    unpack = unpack or table.unpack,
    newproxy = newproxy,
    assert = assert,
    print = print,
    -- Mock exploit APIs
    getgenv = function() return sandbox_env end,
    gethui = function() return {} end,
    setclipboard = function() end,
    toclipboard = function() end,
    request = function() return {} end,
    readfile = function() return "" end,
    writefile = function() end,
    makefolder = function() end,
    Instance = setmetatable({}, {__index = function() return function() return setmetatable({}, {}) end end}),
    Enum = setmetatable({}, {__index = function() return setmetatable({}, {}) end}),
    Color3 = setmetatable({}, {__call = function() return setmetatable({}, {}) end}),
    CFrame = setmetatable({}, {__call = function() return setmetatable({}, {}) end}),
    UDim2 = setmetatable({}, {__call = function() return setmetatable({}, {}) end}),
    Vector3 = setmetatable({}, {__call = function() return setmetatable({}, {}) end}),
    task = {wait = function() end, spawn = function(f) if f then f() end end, delay = function(_, f) if f then f() end end},
    loadstring = function() return nil, "blocked" end,
    game = setmetatable({}, {
        __index = function(t, k)
            if k == "HttpGet" then return function() return "" end end
            if k == "GetService" then return function() return setmetatable({}, {}) end end
            if k == "FindFirstChild" then return function() return nil end end
            if k == "WaitForChild" then return function() return nil end end
            return sandbox_env[k] or setmetatable({}, {})
        end,
        __call = function() return setmetatable({}, {}) end
    }),
}

-- Read source.lua
local f = io.open("/Users/kanishkv/Developer/wcue deobf/source.lua", "r")
if not f then print("Cannot open source.lua") os.exit(1) end
local source = f:read("*a")
f:close()

print("Source length: " .. #source)

-- The source.lua returns a function that takes arguments.
-- The outer structure is:
--   return(function(H,X,l,v,S,K,B,R,u,A,O,q,J,P,L,z,j,b,a,Y,W,U,i,V,T,Z,g,f)
--     ...
--   end)(getfenv and getfenv() or _ENV, unpack or table[I(-738701+722915)], newproxy, setmetatable, getmetatable, select, {...})
-- end)(...)

-- We need to find where the outer invocation begins.
-- The very last "end)(...)" of the file.

-- Strategy: modify source.lua to add hooks before the VM runs.
-- We'll insert code that captures the W[J] decoder after the VM initialization.

-- Actually, the best approach: run source.lua, and since it will try to call
-- executor APIs, we can let it initialize (which sets up H, W, J, etc.)
-- but catch errors when it tries to do real work.

-- The problem is source.lua is a single massive expression. We can't easily
-- insert hooks. Instead, let's try to:
-- 1. Extract just the H table + swap + base64 code
-- 2. Run THAT in the sandbox
-- 3. Then use the resulting H table to build the decoder ourselves

-- Find the end of the base64 decode block (before the VM wrapper)
local function find_base64_end(src, start_pos)
    -- Search for "end)" that closes the do block
    -- The pattern is: do local I={...} ... end
    -- We need matching end for 'do'
    local pos = start_pos
    local depth = 0
    local in_str = false
    local str_char = nil
    local escaped = false
    
    -- Skip to find 'do'
    pos = src:find("do local I=", pos, true)
    if not pos then return nil end
    pos = pos + 2 -- skip 'do'
    depth = 1
    
    -- Now find matching 'end'
    while pos <= #src and depth > 0 do
        local c = src:sub(pos, pos)
        if escaped then
            escaped = false
        elseif in_str then
            if c == "\\" then
                escaped = true
            elseif c == str_char then
                in_str = false
            end
        else
            if c == '"' or c == "'" then
                in_str = true
                str_char = c
            elseif c:find("%w") then
                -- Check for keywords
                -- Look ahead for 'do', 'then', 'function', 'else', 'end'
                local rest = src:sub(pos)
                if rest:match("^end[%s%(%)%+%-%*/%#%,;%]%}%-]") or rest:match("^end$") then
                    depth = depth - 1
                    if depth == 0 then
                        -- Found the matching end
                        -- Skip past 'end'
                        pos = pos + 3 - 1
                        -- Look for closing paren of the do block
                        return pos
                    end
                    pos = pos + 3 - 1
                elseif rest:match("^then[%s%(%)%+%-%*/%#%,%]") then
                    depth = depth + 1
                elseif rest:match("^do[%s%(%)%+%-%*/%#%,%]") then
                    depth = depth + 1
                elseif rest:match("^function[%s%(%)%+%-%*/%#%,%]") then
                    depth = depth + 1
                end
            elseif c == "{" then
                -- table constructors don't affect depth for do/end
            end
        end
        pos = pos + 1
    end
    return nil
end

-- Actually, let me just use a simpler approach.
-- Find "return(function(" which starts the VM wrapper
-- Everything before it is the initialization code
local wrapper_start = source:find("return(function(")
if not wrapper_start then
    -- Try without 'return'
    wrapper_start = source:find("(function(H,X,l,v")
end

print("Wrapper start: " .. (wrapper_start or "NOT FOUND"))

-- The initialization code runs from after 'return' up to wrapper_start
-- Actually, the entire file is structured as:
-- return(function(H,X,l,v,...) ... end)(args)
-- So the 'return' is part of the outer invoking function.
-- But the structure shown at the end of the file shows TWO levels:
-- end)(...end)(...)
-- So there are TWO invocations.

-- Let me find the first 'return(' in the file
local first_return = source:find("return%(")
print("First return(: " .. (first_return or "NOT FOUND"))

-- Let me just look for the H table + init code boundaries
-- We know H table starts at 21 and swap code starts at 410290

-- Let me extract just the initialization portion and run it
local init_code = source:sub(1, (wrapper_start or #source) - 1)

-- Now find where the H table local statement begins
-- The file starts with "return(function(...)\nlocal H={"
-- Let me look at the very beginning
print("First 100 chars: " .. source:sub(1, 100))

-- Actually, let me take a completely different approach.
-- We already have the string pool extracted by the Python script.
-- Let's just use those blobs directly and implement the decoder in pure Lua.

-- Load the string pool
local pool_json = io.open("/Users/kanishkv/Developer/wcue deobf/wcue-decompile/artifacts/string_pool_stage2.json", "r")
if not pool_json then print("Cannot open pool JSON") os.exit(1) end
local pool_data = pool_json:read("*a")
pool_json:close()

-- Parse JSON (simple since it's just an array of objects with hex fields)
-- We need the stage2_hex for each entry
local pool = {}
local idx = 1
for hex_str in pool_data:gmatch('"stage2_hex":%s*"([^"]*)"') do
    pool[idx] = hex_str
    idx = idx + 1
end
print("Loaded " .. #pool .. " pool entries")

-- Now build the decoder in Lua
-- The decoder takes a blob (by H index) and a seed, and returns the decoded string

local function hex_to_bytes(hex)
    local bytes = {}
    for i = 1, #hex, 2 do
        table.insert(bytes, tonumber(hex:sub(i, i+1), 16))
    end
    return bytes
end

local function decode_blob(blob_bytes, seed)
    local state45 = seed % (2^45)
    local state257 = (seed % 255) + 2
    local queue = {}
    local result = {}
    
    for i = 1, #blob_bytes do
        if #queue == 0 then
            -- Refill PRNG
            state45 = (state45 * 177 + 5746771741299) % (2^45)
            state257 = (state257 * 80) % 257
            if state257 == 1 then
                state257 = (state257 * 80) % 257
            end
            
            -- Extract 4 bytes from the 45-bit state and state257
            -- The window is the lower 32 bits of state45
            local window32 = state45 % (2^32)
            
            -- Try the "divisor" approach from Phase Five
            local v_low = state257 % 32
            local v_high = math.floor(state257 / 32)
            if v_high < 1 then v_high = 1 end
            if v_high > 31 then v_high = 31 end
            
            -- Derive power-of-2 divisor from v_high
            local divisor = 2^v_high
            local combined = math.floor(window32 / divisor)
            
            local b0 = combined % 256
            local b1 = math.floor(combined / 256) % 256
            local b2 = math.floor(combined / 65536) % 256
            local b3 = math.floor(combined / 16777216) % 256
            
            -- Use v_low somehow - XOR?
            -- Try different combinations
            
            -- Variant 1: direct, no mixing
            queue = {b0, b1, b2, b3}
        end
        
        local rand_val = table.remove(queue, 1)
        local byte_val = blob_bytes[i]
        local decoded = (byte_val + rand_val + 101) % 256
        table.insert(result, string.char(decoded))
    end
    
    return table.concat(result), state45, state257
end

local function printable_ratio(s)
    local count = 0
    for i = 1, #s do
        local c = string.byte(s, i)
        if (c >= 32 and c < 127) or c == 9 or c == 10 or c == 13 then
            count = count + 1
        end
    end
    if #s == 0 then return 0 end
    return count / #s
end

-- Test targets from Phase Four
local targets = {
    {2772, 2496212501642, "GetService name 1?"},
    {4854, 1186289386024, "GetService name 2?"},
    {3204, 30916575737916, "GetService name 3?"},
    {5619, 32879211232206, "GetService name 4?"},
    {693, 17652829380636, "GetService name 5?"},
    {2704, 14670855527087, "HttpGet URL"},
    {1542, 3007687984504, "getgenv slot"},
    {3869, 11301675111566, "HttpGet URL 2"},
    {942, 3732199540425, "getgenv slot 2"},
    {2271, 2668542641370, "Instance.new?"},
    {3615, 19901264536627, "class name?"},
    {5641, 14043772639627, "prefix"},
    {5897, 33213205888106, "suffix 1"},
    {6860, 2711126017262, "suffix 2"},
    {2811, 3575791224449, "suffix 3"},
    {106, 2711126017262, "suffix 4"},
}

-- Try multiple refill approaches
local refill_variants = {
    function(state45, state257)
        -- v1: window32 / divisor, 4 bytes, no v_low mixing
        local window32 = state45 % (2^32)
        local v_high = math.floor(state257 / 32)
        if v_high < 1 then v_high = 1 end
        if v_high > 31 then v_high = 31 end
        local divisor = 2^v_high
        local combined = math.floor(window32 / divisor)
        return {
            combined % 256,
            math.floor(combined / 256) % 256,
            math.floor(combined / 65536) % 256,
            math.floor(combined / 16777216) % 256
        }
    end,
    function(state45, state257)
        -- v2: window32 / divisor, 4 bytes, XOR with v_low
        local window32 = state45 % (2^32)
        local v_low = state257 % 32
        local v_high = math.floor(state257 / 32)
        if v_high < 1 then v_high = 1 end
        if v_high > 31 then v_high = 31 end
        local divisor = 2^v_high
        local combined = math.floor(window32 / divisor)
        return {
            (combined % 256) ~ v_low,
            (math.floor(combined / 256) % 256) ~ v_low,
            (math.floor(combined / 65536) % 256) ~ v_low,
            (math.floor(combined / 16777216) % 256) ~ v_low
        }
    end,
    function(state45, state257)
        -- v3: simple 32-bit window, 4 bytes big-endian
        local window32 = state45 % (2^32)
        return {
            math.floor(window32 / 16777216) % 256,
            math.floor(window32 / 65536) % 256,
            math.floor(window32 / 256) % 256,
            window32 % 256
        }
    end,
    function(state45, state257)
        -- v4: simple 32-bit window, 4 bytes little-endian
        local window32 = state45 % (2^32)
        return {
            window32 % 256,
            math.floor(window32 / 256) % 256,
            math.floor(window32 / 65536) % 256,
            math.floor(window32 / 16777216) % 256
        }
    end,
    function(state45, state257)
        -- v5: use full 45-bit state, shifted by state257
        local v_low = state257 % 32
        local shifted = math.floor(state45 / (2^v_low))
        return {
            shifted % 256,
            math.floor(shifted / 256) % 256,
            math.floor(shifted / 65536) % 256,
            math.floor(shifted / 16777216) % 256
        }
    end,
    function(state45, state257)
        -- v6: use state257 as shift amount for 32-bit window
        local v_low = state257 % 32
        local window32 = state45 % (2^32)
        local shifted = math.floor(window32 / (2^v_low))
        return {
            shifted % 256,
            math.floor(shifted / 256) % 256,
            math.floor(shifted / 65536) % 256,
            math.floor(shifted / 16777216) % 256
        }
    end,
}

local decode_constants = {101, 0, -101, 155, 256-101}

print("\nTesting decoder variants...")
print(string.format("%-8s %-14s %-6s %-6s %-20s %-30s", "H[idx]", "seed", "len", "var", "const", "result"))

for _, target in ipairs(targets) do
    local h_idx, seed, desc = target[1], target[2], target[3]
    local hex = pool[h_idx]
    if hex then
        local blob = hex_to_bytes(hex)
        local best_printable = 0
        local best_result = ""
        local best_variant = ""
        local best_const = 0
        
        for vi, refill in ipairs(refill_variants) do
            for _, const in ipairs(decode_constants) do
                local state45 = seed % (2^45)
                local state257 = (seed % 255) + 2
                local queue = {}
                local result_parts = {}
                local ok = true
                
                for i = 1, #blob do
                    if #queue == 0 then
                        state45 = (state45 * 177 + 5746771741299) % (2^45)
                        state257 = (state257 * 80) % 257
                        if state257 == 1 then
                            state257 = (state257 * 80) % 257
                        end
                        local bytes = refill(state45, state257)
                        for _, b in ipairs(bytes) do
                            table.insert(queue, b)
                        end
                    end
                    
                    local rand_val = table.remove(queue, 1)
                    local byte_val = blob[i]
                    local decoded = (byte_val + rand_val + const) % 256
                    table.insert(result_parts, string.char(decoded))
                end
                
                local result_str = table.concat(result_parts)
                local pr = printable_ratio(result_str)
                if pr > best_printable then
                    best_printable = pr
                    best_result = result_str
                    best_variant = "v" .. vi
                    best_const = const
                end
            end
            
            -- Also try subtractive variants
            for _, const in ipairs({0, 101, -101}) do
                local state45 = seed % (2^45)
                local state257 = (seed % 255) + 2
                local queue = {}
                local result_parts = {}
                
                for i = 1, #blob do
                    if #queue == 0 then
                        state45 = (state45 * 177 + 5746771741299) % (2^45)
                        state257 = (state257 * 80) % 257
                        if state257 == 1 then
                            state257 = (state257 * 80) % 257
                        end
                        local bytes = refill(state45, state257)
                        for _, b in ipairs(bytes) do
                            table.insert(queue, b)
                        end
                    end
                    
                    local rand_val = table.remove(queue, 1)
                    local byte_val = blob[i]
                    -- Try: decoded = (byte - rand - const) % 256
                    local decoded = (byte_val - rand_val - const) % 256
                    table.insert(result_parts, string.char(decoded))
                end
                
                local result_str = table.concat(result_parts)
                local pr = printable_ratio(result_str)
                if pr > best_printable then
                    best_printable = pr
                    best_result = result_str
                    best_variant = "v" .. vi .. "-sub"
                    best_const = const
                end
            end
        end
        
        local preview = best_result:gsub("[^%w%p%s]", "?"):sub(1, 50)
        print(string.format("H[%-4d] %-14d %-6d v%-6s c=%-6d p=%.2f %s", 
            h_idx, seed, #blob, best_variant, best_const, best_printable, preview))
    end
end

print("\nDone.")