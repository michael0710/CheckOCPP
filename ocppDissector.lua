-- Define the WebSocket dissector
ocpp_proto = Proto("ocpp", "Open Charge Point Protocol Dissector")

-- Set the locale to standard C value as cjson would otherwise store numbers from the json files
-- with a comma (,) as decimal separator. This would break the jsonschema module.
os.setlocale("C")

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
ocpp_proto.prefs.schemas21  = Pref.string("Path to OCPPv2.1 schemas:",   "", "Path to OCPPv2.1 schemas")

local OCPP_ALL_VERSIONS = 0
local OCPP_1_6          = 1
local OCPP_2_0          = 2
local OCPP_2_0_1        = 3
local OCPP_2_1          = 4
local OCPP_VERS_2_DISSECT = {
    { 1, "all versions" , OCPP_ALL_VERSIONS },
    { 2, "1.6"          , OCPP_1_6 },
    { 3, "2.0"          , OCPP_2_0 },
    { 4, "2.0.1"        , OCPP_2_0_1 },
    { 5, "2.1"          , OCPP_2_1 },
}

-- Create enum preference that shows as Combo Box under
-- Foo Protocol's preferences
ocpp_proto.prefs.proto_version = Pref.enum(
    "Protocol version to dissect",      -- label
    OCPP_ALL_VERSIONS,                  -- default value
    "Protocol version to be dissected", -- description
    OCPP_VERS_2_DISSECT,                -- enum table
    false                               -- show as combo box
)

-- Define fields for the protocol
local f_message_type = ProtoField.uint8("ocpp2.0.1.message_type", "Message Type", base.DEC)
local f_message_id = ProtoField.string("ocpp2.0.1.message_id", "Message ID")
local f_message_name = ProtoField.string("ocpp2.0.1.message_name", "Message Name")
local f_payload = ProtoField.string("ocpp2.0.1.payload", "Payload (JSON)")
local f_valid = ProtoField.bool("ocpp1.6.valid", "Valid?", base.NONE)
local f_ipv6 = ProtoField.bool("ocpp1.6.ipv6", "IPv6?", base.NONE)

local f_ipv6_expert = ProtoExpert.new("IPv6", "Expected IPv6, but packet is IPv4", expert.group.PROTOCOL, expert.severity.WARN)
local f_valid_expert = ProtoExpert.new("OCPP_non_compliant", "OCPP non-compliant packet", expert.group.MALFORMED, expert.severity.ERROR)

ocpp_proto.experts = { f_ipv6_expert, f_valid_expert }

ocpp_proto.fields = {f_message_type, f_message_id, f_message_name, f_payload}

local ocpputil = require("ocpputil")

-- Table to store loaded schemas
local areSchemasLoaded = false
local schemas21  = {}
local schemas201 = {}
local schemas20  = {}
local schemas16  = {}
-- as the responses do not contain the message name, but the id of request
-- and response is the same, we have to keep track of which id corresponds
-- to which message name.
-- According to:
-- OCPP-1.6J specification 4.2.2. CallResult
-- OCPP-2.0.1J specification 4.2.2. CallResult
-- OCPP-2.1J specification 4.2.2. CallResult
local msg_name_id_lut = {}

local function advanced_get(tbl, key_col, value_col, key)
    for idx, entry in next, tbl do
        if entry[key_col] == key then
            return true, entry[value_col]
        end
    end
    return false, ""
end

-- reload schemas when preferences are changed
function ocpp_proto.prefs_changed()
    print("*************************2.1*************************")
    schemas21 = {}
    ocpputil.load_schema(ocpp_proto.prefs.schemas21, schemas21)
    print("************************2.0.1************************")
    schemas201 = {}
    ocpputil.load_schema(ocpp_proto.prefs.schemas201, schemas201)
    print("*************************2.0*************************")
    schemas20 = {}
    ocpputil.load_schema(ocpp_proto.prefs.schemas20, schemas20)
    print("*************************1.6*************************")
    schemas16 = {}
    ocpputil.load_schema(ocpp_proto.prefs.schemas16, schemas16)
    print("************* Finished loading schemas **************")
    areSchemasLoaded = true
end

-- Function to validate JSON against a schema
local function validate_json(payload, schema_name)
    local success16 = false
    local err16 = ""
    local success20 = false
    local err20 = ""
    local success201 = false
    local err201 = ""
    local success21 = false
    local err21 = ""

    -- Handle schema16 validation
    if    (ocpp_proto.prefs.proto_version == OCPP_ALL_VERSIONS)
       or (ocpp_proto.prefs.proto_version == OCPP_1_6) then
        local status16, result16 = pcall(function()
            print("schema_name is: " .. schema_name)
            local key16 = schema_name:gsub("Request$", "")
            success16, err16 = ocpputil.validate_schema(payload, schemas16, key16)
        end)
        if not status16 then
            print("Error in V16 validation: ", result16)
            return false, result16, "None"
        end
    end

    -- Handle schema20 validation
    if    (ocpp_proto.prefs.proto_version == OCPP_ALL_VERSIONS)
       or (ocpp_proto.prefs.proto_version == OCPP_2_0) then
        local status20, result20 = pcall(function()
            success20, err20 = ocpputil.validate_schema(payload, schemas20, schema_name)
        end)
        if not status20 then
            print("Error in V20 validation: ", result20)
        end
    end

    -- Handle schema201 validation
    if    (ocpp_proto.prefs.proto_version == OCPP_ALL_VERSIONS)
       or (ocpp_proto.prefs.proto_version == OCPP_2_0_1) then
        local status201, result201 = pcall(function()
            success201, err201 = ocpputil.validate_schema(payload, schemas201, schema_name)
        end)
        if not status201 then
            print("Error in V201 validation: ", result201)
        end
    end

    -- Handle schema21 validation
    if    (ocpp_proto.prefs.proto_version == OCPP_ALL_VERSIONS)
       or (ocpp_proto.prefs.proto_version == OCPP_2_1) then
        local status21, result21 = pcall(function()
            success21, err21 = ocpputil.validate_schema(payload, schemas21, schema_name)
        end)
        if not status21 then
            print("Error in V21 validation: ", result21)
        end
    end

    -- pack the validated procotol versions in a string
    local vers_str = ''
    -- flag the message as 'All' if the validation succeeded for
    -- all schemas that are registered
    if     (success16  or (ocpp_proto.prefs.schemas16  == ''))
       and (success20  or (ocpp_proto.prefs.schemas20  == '')) 
       and (success201 or (ocpp_proto.prefs.schemas201 == '')) 
       and (success21  or (ocpp_proto.prefs.schemas21  == '')) then
        vers_str = 'All'
    else
        if success16 then
            if not (vers_str == '') then
                vers_str = vers_str .. '/1.6'
            else
                vers_str = '1.6'
            end
        end

        if success20 then
            if not (vers_str == '') then
                vers_str = vers_str .. '/2.0'
            else
                vers_str = '2.0'
            end
        end

        if success201 then
            if not (vers_str == '') then
                vers_str = vers_str .. '/2.0.1'
            else
                vers_str = '2.0.1'
            end
        end

        if success21 then
            if not (vers_str == '') then
                vers_str = vers_str .. '/2.1'
            else
                vers_str = '2.1'
            end
        end
    end

    if success16 or success20 or success201 or success21 then
        return true, nil, vers_str
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
        -- usually wireshark calls the prefs_changed() function on startup
        -- and hereby loads our schemas. However, somehow I don't trust
        -- that feature, so make sure the schemas are loaded here.
        ocpp_proto.prefs_changed()
    end
    
    local length = buffer:len()
    local ipv6 = false
    if length == 0 then return end

    print("New Packet!!! ***************************************")

    print(pinfo.src)
    if tostring(pinfo.src):match("^(%d+%.%d+%.%d+%.%d+)$") then
        ipv6 = false
    elseif tostring(pinfo.src):match("^([a-fA-F0-9:]+)$") then
        ipv6 = true
    end

    -- Convert buffer to a string
    local payload = buffer():string()

    -- Extract elements from the JSON array
    local elements = ocpputil.parseJSONArray(payload)

    -- Extract individual elements
    local message_type = tonumber(elements[1])
    print(string.format("Type: %s", tostring(message_type)))
    local message_id = ocpputil.cleanElement(elements[2]:gsub('^["\'](.-)["\']$', '%1'))
    print(string.format("ID: %s", tostring(message_id)))
    local message_name = ""
    if not(message_type == 3) then
        message_name = ocpputil.cleanElement(elements[3]:gsub('^["\'](.-)["\']$', '%1'))
        msg_name_id_lut[message_id] = message_name
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
        -- get the actual message name from our look-up-table
        full_message_name = msg_name_id_lut[message_id]:gsub('["]', '') .. "Response"
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
        subtree:add(f_valid, is_valid):set_hidden(true)
        if not ipv6 then
            subtree:add(f_ipv6, false):set_hidden(true)
            subtree:add_proto_expert_info(f_ipv6_expert)
        end
        subtree:add(f_message_type, buffer(1, 1), message_type):append_text(" (2=Request, 3=Response, 4=Error)")
        subtree:add(f_message_id, buffer(3, #message_id), message_id)
        if message_type == 3 then
            subtree:add(f_message_name, msg_name_id_lut[message_id]):append_text(" (implicit by ID)")
        else
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
    else
        if not (ocpp_proto.prefs.proto_version == OCPP_ALL_VERSIONS) then
            local rv, vers_str = advanced_get(OCPP_VERS_2_DISSECT, 3, 2, ocpp_proto.prefs.proto_version)
            pinfo.cols.protocol = "OCPP " .. vers_str
            local subtree = tree:add(ocpp_proto, buffer(), "OCPP Non-Compliant Packet")
            subtree:add(ProtoField.string("ocpp" .. vers_str .. ".error", "Error"), buffer(), tostring(validation_error))
            subtree:add(f_valid, is_valid):set_hidden(true)
            subtree:add_proto_expert_info(f_valid_expert)
            if not ipv6 then
                subtree:add(f_ipv6, false):set_hidden(true)
                subtree:add_proto_expert_info(f_ipv6_expert)
            end
        end
    end
end

-- Register the dissector
local ws_protocol_table = DissectorTable.get("ws.protocol")
ws_protocol_table:add("ocpp2.0.1", ocpp_proto)
ws_protocol_table:add("ocpp2.0", ocpp_proto)
ws_protocol_table:add("ocpp1.6", ocpp_proto)
