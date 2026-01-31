local ocpputil = { }

local cjson = require("cjson")
local jsonschema = require("jsonschema")

local function is_windows_platform()
    local pathseparator = package.config:sub(1,1);
    if pathseparator == "\\" then
        return true
    else
        return false
    end
end

local function remove_bom(content)
    local bom = "\239\187\191" -- EF BB BF in decimal
    if content:sub(1, 3) == bom then
        return content:sub(4) -- Remove the first three bytes
    end
    return content
end

local function remove_id_property(schema)
    if type(schema) == "table" then
        schema["$id"] = nil -- Remove the $id key
        for key, value in pairs(schema) do
            remove_id_property(value) -- Recursively remove $id in nested objects
        end
    end
end

local function jsonToLua(jsonStr)
    -- Decode the JSON string into a Lua table
    local success, result = pcall(cjson.decode, jsonStr)
    if not success then
        error("Invalid JSON format: " .. tostring(result))
    end

    return result
end

local function cleanElement(str)
    return str:match("^%s*,?%s*(.-)%s*$") -- Remove leading comma and spaces
end

local function parseJSONArray(jsonStr)
    -- check if the outer square brackets exist
    if    (jsonStr:sub(1,1) ~= "[")
       or (jsonStr:sub(#jsonStr, #jsonStr) ~= "]") then
        return false, nil
    end

    local parts = {}
    local in_quotes = false
    local escape = false
    local buffer = ""
    local bracket_count = 0

    for i = 2, #jsonStr - 1 do -- Ignore the outer square brackets
        local char = jsonStr:sub(i, i)

        if char == '"' and not escape then
            in_quotes = not in_quotes
        elseif char == "\\" and in_quotes then
            escape = not escape
        elseif char == "{" or char == "[" then
            if not in_quotes then
                bracket_count = bracket_count + 1
            end
        elseif char == "}" or char == "]" then
            if not in_quotes then
                bracket_count = bracket_count - 1
            end
        elseif char == "," and not in_quotes and bracket_count == 0 then
            -- Push completed element to parts
            parts[#parts + 1] = buffer:match("^%s*(.-)%s*$") -- Trim whitespace
            buffer = ""
        else
            escape = false
        end

        buffer = buffer .. char
    end

    -- do a little validity check here
    if    in_quotes
       or (bracket_count ~= 0) then
        return false, nil
    end

    -- Add the last element
    parts[#parts + 1] = buffer:match("^%s*(.-)%s*$") -- Trim whitespace
    return true, parts
end

local function printLuaTable(tbl, indent)
    indent = indent or 0 -- Track the indentation level
    local padding = string.rep("  ", indent) -- Indent with spaces
    for key, value in pairs(tbl) do
        if type(value) == "table" then
            -- Print the key and recurse into the nested table
            print(padding .. "\"" .. tostring(key) .. "\"" .. " : {")
            printLuaTable(value, indent + 1)
            print(padding .. "}")
        else
            -- Print the key-value pair
            if (type(value) == "number") then
                print(padding .. "\"" .. tostring(key) .. "\"" .. " : " .. tostring(value) .. " (number)")
            else
                print(padding .. "\"" .. tostring(key) .. "\"" .. " : " .. tostring(value))
            end
        end
    end
end

local function validate_schema(payload, schema_group, schema_name_key)
    local schema = schema_group[schema_name_key]
    if not schema then
        return false, "Schema not found for: " .. tostring(schema_name_key)
    end
    
    -- Safely execute schema validation
    local success, err = schema(payload)
    if not success then
        return false, "Error during schema validation: " .. tostring(err)
    end
    return true, nil
end

local function load_schema(schema_dir, schema_var)
    if schema_dir == "" then
        print("schema_dir is empty, load_schema skipped")
        return
    end
    print("schema_dir is " .. schema_dir)
    local is_windows = is_windows_platform()
    local files = nil
    if is_windows == true then
        local popen_rv = io.popen("dir " .. schema_dir:gsub("/", "\\"))   -- List files in schema_dir   windows needs dir and an extra sausage
        files = popen_rv:lines()
    else -- otherwise assume unix
        files = io.popen('ls ' .. schema_dir):lines()         -- List files in schema_dir   linux needs ls
    end
    for line in files do
        local file = line:match("[%a%d%-_]+%.json")
        if file ~= nil then
            local schema_path = schema_dir .. "/" .. file
            local schema_file = io.open(schema_path, "r") -- Open the schema file
            if schema_file then
                print("processing schema file: " .. schema_path)
                local schema_content = schema_file:read("*all") -- Read schema content
                schema_content = remove_bom(schema_content)
                schema_file:close()
                local success, schema = pcall(cjson.decode, schema_content)
                if success then
                    -- set locale to "C" temporarily
                    -- (workaround until the jsonschema module is fixed
                    --  see https://github.com/api7/jsonschema/issues/95)
                    active_locale = os.setlocale(nil)
                    os.setlocale("C")
                    local success_validator, compiled_schema = pcall(jsonschema.generate_validator, schema)
                    if success_validator then
                        -- Store the compiled schema
                        local schema_name = file:gsub("%.json$", ""):gsub("_v%d+p%d+$", "")
                        schema_var[schema_name] = compiled_schema
                    else
                        print("Call to generate_validator not successful: " .. compiled_schema)
                        -- Retry after removing $id
                        -- (workaround until jsonschema is fixed
                        --  see https://github.com/api7/jsonschema/issues/67)
                        print("Retrying " .. file .. " after removing $id")
                        remove_id_property(schema)
                        success_validator, compiled_schema = pcall(jsonschema.generate_validator, schema)
                        if success_validator then
                            local schema_name = file:gsub("%.json$", ""):gsub("_v%d+p%d+$", "")
                            schema_var[schema_name] = compiled_schema
                        else
                            print("Error compiling schema for file after removing $id: " .. file .. ": " .. compiled_schema)
                            print("Schema is:")
                            print("{")
                            printLuaTable(schema, 1)
                            print("}")
                        end
                    end
                    os.setlocale(active_locale)
                else
                    print("Error decoding schema for file: " .. file .. ": " .. schema)
                end
            else
                print("Error opening schema file: " .. schema_path)
            end
        end
    end
end

ocpputil.remove_bom            = remove_bom
ocpputil.remove_id_property    = remove_id_property
ocpputil.jsonToLua             = jsonToLua
ocpputil.cleanElement          = cleanElement
ocpputil.parseJSONArray        = parseJSONArray
ocpputil.validate_schema       = validate_schema
ocpputil.load_schema           = load_schema
ocpputil.printLuaTable         = printLuaTable

return ocpputil
