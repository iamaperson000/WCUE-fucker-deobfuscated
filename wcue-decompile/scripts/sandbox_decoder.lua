#!/usr/bin/env lua
-- WCUE Direct Decoder: Extract the string pool + swap + base64 + then the W[J] decoder
-- by running just the relevant parts of source.lua in isolation
--
-- The plan:
-- 1. Read source.lua
-- 2. Extract just the H table initialization code + swap + base64 decode
-- 3. After that runs, H is populated with the decoded strings
-- 4. Then extract the W[J] decoder setup portion and instrument it
-- 5. Call the decoder for each (blob, seed) target

local function main()
    -- Read source
    local f = io.open("/Users/kanishkv/Developer/wcue deobf/source.lua", "r")
    if not f then print("Cannot open source.lua") os.exit(1) end
    local source = f:read("*a")
    f:close()
    
    -- Find the H table start
    local h_start = source:find("local H={")
    if not h_start then print("Cannot find H table") os.exit(1) end
    print("H table starts at offset: " .. h_start)
    
    -- Find the H table end (matching })
    local depth = 0
    local h_end = nil
    local i = source:find("{", h_start)
    depth = 1
    i = i + 1
    local in_string = false
    local string_quote = nil
    local escaped = false
    
    while i <= #source and depth > 0 do
        local c = source:sub(i, i)
        
        if escaped then
            escaped = false
        elseif in_string then
            if c == "\\" then
                escaped = true
            elseif c == string_quote then
                in_string = false
            end
        else
            if c == '"' or c == "'" then
                in_string = true
                string_quote = c
            elseif c == "{" then
                depth = depth + 1
            elseif c == "}" then
                depth = depth - 1
                if depth == 0 then
                    h_end = i
                    break
                end
            end
        end
        i = i + 1
    end
    
    if not h_end then print("Cannot find end of H table") os.exit(1) end
    print("H table ends at offset: " .. h_end)
    
    -- Extract everything from H table start to end of file 
    -- (includes swap, base64 decode, and the VM)
    local h_init = source:sub(h_start, h_end)
    
    -- Now find the swap range code and base64 decode code
    -- The structure is:
    -- local H={...}  (string pool)
    -- for I,a in ipairs({...}) do ... end  (swap ranges)
    -- do local I={...} ... end  (base64 decode using custom alphabet)
    -- return(function(...) ... end)(...)  (VM)
    
    -- Find the swap range code
    local swap_start = source:find("for I,a in ipairs", h_end)
    print("Swap code starts at: " .. (swap_start or "NOT FOUND"))
    
    -- Find the base64 decode block
    local b64_start = source:find("do local I={", h_end)
    print("Base64 block starts at: " .. (b64_start or "NOT FOUND"))
    
    -- Find the return(function wrapper
    local wrapper_start = source:find("return(function(", b64_start or h_end)
    print("Wrapper starts at: " .. (wrapper_start or "NOT FOUND"))
    
    -- The approach: extract just the H table + swap + base64 decode
    -- and run that to populate H
    
    -- Find the end of the base64 decode block
    -- It's a do...end block
    local b64_end = nil
    if b64_start then
        -- Find matching end
        local search_pos = b64_start
        depth = 0
        local j = search_pos
        while j <= #source do
            local c = source:sub(j, j)
            -- Simple approach: find "end)" which closes the do block
            -- Actually find matching end for 'do'
            j = j + 1
        end
        
        -- Just look for the wrapper_start which comes after base64
        if wrapper_start then
            b64_end = wrapper_start - 1
        end
    end
    
    print("B64 block ends at: " .. (b64_end or "NOT FOUND"))
    
    -- Extract the initialization code (H table + swap + base64 decode)
    local init_code_end = wrapper_start or #source
    local init_code = source:sub(h_start, init_code_end - 1)
    
    print("Init code length: " .. #init_code)
    
    -- Now we need to run this code in an environment
    -- But first, let's try a simpler approach:
    -- Just extract the string pool data directly using our Python extractor
    -- and then feed it into the VM
    
    -- Let's look at the end of the file to understand how the VM is invoked
    local last_500 = source:sub(#source - 500)
    print("\nLast 500 chars of source.lua:")
    print(last_500)
end

main()