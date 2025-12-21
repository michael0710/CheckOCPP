-- Define the WebSocket dissector
ocpp_proto = Proto("ocpp", "Open Charge Point Protocol Dissector")

-- Define preferences for the plugin
--[[
local schemaTableList = {
    {"OCPPv1.6"  , ""},
    {"OCPPv2.0"  , ""},
    {"OCPPv2.0.1", ""},
}
ocpp_proto.prefs.schemaTable = Pref.uat("Paths to the OCPP schemas", schemaTableList, "Paths to the OCPP schemas", "testFileName")
]]
ocpp_proto.prefs.schemas16  = Pref.string("Path to OCPPv1.6 schemas:  ", "", "Path to OCPPv1.6 schemas")
ocpp_proto.prefs.schemas20  = Pref.string("Path to OCPPv2.0 schemas:  ", "", "Path to OCPPv2.0 schemas")
ocpp_proto.prefs.schemas201 = Pref.string("Path to OCPPv2.0.1 schemas:", "", "Path to OCPPv2.0.1 schemas")

-- Define fields for the protocol
local f_message_type = ProtoField.uint8("ocpp2.0.1.message_type", "Message Type", base.DEC)
local f_message_id = ProtoField.string("ocpp2.0.1.message_id", "Message ID")
local f_message_name = ProtoField.string("ocpp2.0.1.message_name", "Message Name")
local f_payload = ProtoField.string("ocpp2.0.1.payload", "Payload (JSON)")

ocpp_proto.fields = {f_message_type, f_message_id, f_message_name, f_payload}

local ocpputil = require("ocpputil")

-- Table to store loaded schemas
local areSchemasLoaded = false
local schemas201 = {}
local schemas20 = {}
local schemas16 = {}

-- Function to validate JSON against a schema
local function validate_json(payload, schema_name)
    local function validate_schema(schema_group, schema_name_key)
        local schema = schema_group[schema_name_key]
        if not schema then
            return false, "Schema not found for: " .. tostring(schema_name_key)
        end
        
        -- Safely execute schema validation
        local success, err = schema(payload)
        if not success then
            return false, "Error during schema validation: " .. tostring(err)
        end
        return success, nil
    end

    local success16, err16
    local success20, err20
    local success201, err201

    -- Handle schema16 validation
    local status16, result16 = pcall(function()
        local key16 = schema_name:gsub("Request$", "")
        success16, err16 = validate_schema(schemas16, key16)
    end)
    if not status16 then
        print("Error in V16 validation: ", result16)
        return false, result16, "None"
    end

    -- Handle schema20 validation
    local status20, result20 = pcall(function()
        success20, err20 = validate_schema(schemas20, schema_name)
    end)
    if not status20 then
        print("Error in V20 validation: ", result20)
    end

    -- Handle schema201 validation
    local status201, result201 = pcall(function()
        success201, err201 = validate_schema(schemas201, schema_name)
    end)
    if not status201 then
        print("Error in V201 validation: ", result201)
    end

    -- Decision logic remains the same
    if success16 and success20 and success201 then
        return true, nil, 'All'
    elseif success16 and success20 then
        return true, nil, '1.6/2.0'
    elseif success16 and success201 then
        return true, nil, '1.6/2.0.1'
    elseif success20 and success201 then
        return true, nil, '2.0/2.0.1'
    elseif success16 then
        return success16, err16, '1.6'
    elseif success20 then
        return success20, err20, '2.0'
    elseif success201 then
        return success201, err201, '2.0.1'
    else
        return false, tostring(err16) .. '   ' .. tostring(err20) .. '   ' .. tostring(err201), 'None'
    end
end

function printLuaTable(tbl, indent)
    indent = indent or 0 -- Track the indentation level
    local padding = string.rep("  ", indent) -- Indent with spaces
    for key, value in pairs(tbl) do
        if type(value) == "table" then
            -- Print the key and recurse into the nested table
            print(padding .. tostring(key) .. " => {")
            printLuaTable(value, indent + 1)
            print(padding .. "}")
        else
            -- Print the key-value pair
            print(padding .. tostring(key) .. " => " .. tostring(value))
        end
    end
end

-- Dissector function
function ocpp_proto.dissector(buffer, pinfo, tree)
    if areSchemasLoaded == false then
        print("************************2.0.1************************")
        ocpputil.load_schema(ocpp_proto.prefs.schemas201, schemas201)
        print("*************************2.0*************************")
        ocpputil.load_schema(ocpp_proto.prefs.schemas20, schemas20)
        print("*************************1.6*************************")
        ocpputil.load_schema(ocpp_proto.prefs.schemas16, schemas16)
        areSchemasLoaded = true
    end
    
    local length = buffer:len()
    if length == 0 then return end

    print('New Packet!!!')
    print('\n')

    -- Convert buffer to a string
    local payload = buffer():string()

    -- Extract elements from the JSON array
    local elements = ocpputil.parseJSONArray(payload)

    -- Extract individual elements
    local message_type = tonumber(elements[1])
    print(string.format("Type: %s", tostring(message_type)))
    local message_id = ocpputil.cleanElement(elements[2]:gsub('^["\'](.-)["\']$', '%1'))
    print(string.format("ID: %s", tostring(message_id)))
    if not(message_type == 3) then
        message_name = ocpputil.cleanElement(elements[3]:gsub('^["\'](.-)["\']$', '%1'))
        print(string.format("Name: %s", tostring(message_name)))
        json_data_str = ocpputil.cleanElement(elements[4]) 
    else
        json_data_str = ocpputil.cleanElement(elements[3]) 
    end

    print(string.format("Data: %s", tostring(json_data_str)))
    print('\n')

    -- Parse and display JSON if possible
    local json_data = ocpputil.jsonToLua(json_data_str)
    print('LUA Table:')
    printLuaTable(json_data)
    print('\n\n')

    local full_message_name = "" -- Variable to hold the result

    if message_type == 2 then
        full_message_name = message_name:gsub('["]', '') .. "Request"
    elseif message_type == 3 then
        full_message_name = message_name:gsub('["]', '') .. "Response"
    end

    local is_valid, validation_error, version = validate_json(json_data, full_message_name)
    print(string.format("VALID?: %s", tostring(is_valid)))
    print(string.format("ERROR?: %s", tostring(validation_error)))
    print(string.format("VERSION?: %s", tostring(version)))
    print('\n')

    if is_valid then
        
        if version == 'All' then
            pinfo.cols.protocol = "OCPP"
        else
            pinfo.cols.protocol = "OCPP " .. version
        end

        -- Create the protocol tree
        local subtree = tree:add(ocpp_proto, buffer(), "OCPP Protocol Payload")

        
        -- Add elements to the tree
        subtree:add(f_message_type, buffer(1, 1), message_type):append_text(" (2=Request, 3=Response, 4=Error)")
        subtree:add(f_message_id, buffer(3, #message_id), message_id)
        if not(message_type == 3) then 
            subtree:add(f_message_name, buffer(#message_id + 4, #message_name), message_name)
        end

        

        if json_data then
            if not(message_type == 3) then 
                payload_tree = subtree:add(f_payload, buffer(3 + #message_id + #message_name +2, buffer:len()-(3 + #message_id + #message_name +2)-1), "Payload")
            else
                payload_tree = subtree:add(f_payload, buffer(3 + #message_id + 1, buffer:len()-(3 + #message_id)-2), "Payload")
            end

            -- Recursive function to add key-value pairs
            local function add_key_value_pairs(tree, data, prefix)
                for key, value in pairs(data) do
                    -- Ensure the key ends with ":"
                    local formatted_key = tostring(key):find(":$") and tostring(key) or (tostring(key) .. ":")
                    if type(value) == "table" then
                        -- If the value is a dictionary, create a new subtree and recurse
                        local nested_tree = tree:add(formatted_key, "Nested Data")
                        add_key_value_pairs(nested_tree, value, prefix .. "  ")
                    else
                        -- Otherwise, add the key-value pair
                        tree:add(formatted_key, tostring(value))
                    end
                end
            end

            -- Process the JSON data
            add_key_value_pairs(payload_tree, json_data, "")
        else
            subtree:add(f_payload, buffer(#message_name + 2), "Invalid JSON")
        end
    end
end

-- Register the dissector
local ws_protocol_table = DissectorTable.get("ws.protocol")
ws_protocol_table:add("ocpp2.0.1", ocpp_proto)
ws_protocol_table:add("ocpp2.0", ocpp_proto)
ws_protocol_table:add("ocpp1.6", ocpp_proto)
