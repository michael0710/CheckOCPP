-- Define the WebSocket dissector
-- the overall OCPP dissector is only used to store the common preferences
ocpp_proto = Proto("ocpp", "Open Charge Point Protocol Dissector")

local OCPP_JSON_VERSIONS = {
    "1.6",
    "2.0",
    "2.0.1",
    "2.1",
}

-- the version specific dissectors are registered here
ocpp_proto_list = {}
for idx, version in pairs(OCPP_JSON_VERSIONS) do
    ocpp_proto_list[version] = Proto("ocpp" .. version .. "j",   "Open Charge Point Protocol version " .. version .. "J")
end

-- Define preferences for the plugin
for idx, version in pairs(OCPP_JSON_VERSIONS) do
    ocpp_proto.prefs["schemas" .. version .. "j"] = Pref.string("Path to OCPPv" .. version .. " JSON-schemas:  ", "", "Path to OCPPv" .. version .. " JSON-schemas")
end

-- Define fields for the protocol
local f_message_type = ProtoField.uint8("ocpp.message_type", "Message Type", base.DEC)
local f_message_id = ProtoField.string("ocpp.message_id", "Message ID")
local f_message_name = ProtoField.string("ocpp.message_name", "Message Name")
local f_payload = ProtoField.string("ocpp.payload", "Payload (JSON)")
local f_valid = ProtoField.bool("ocpp.valid", "Valid?", base.NONE)
local f_version = ProtoField.string("ocpp.version", "Protocol version")
local f_ipv6 = ProtoField.bool("ocpp.ipv6", "IPv6?", base.NONE)

local f_ipv6_expert = ProtoExpert.new("IPv6", "Expected IPv6, but packet is IPv4", expert.group.PROTOCOL, expert.severity.WARN)
local f_valid_expert = ProtoExpert.new("OCPP_non_compliant", "OCPP non-compliant packet", expert.group.MALFORMED, expert.severity.ERROR)
local f_missing_schema_expert = ProtoExpert.new("OCPP_no_schema_provided", "OCPP JSON-schemas missing", expert.group.REASSEMBLE, expert.severity.WARN)
local f_wrong_version_expert = ProtoExpert.new("OCPP_non_compliant_version", "OCPP non-compliant packet, but compliant with other OCPP version", expert.group.MALFORMED, expert.severity.ERROR)

ocpp_proto.experts = { f_ipv6_expert, f_valid_expert, f_missing_schema_expert, f_wrong_version_expert }
ocpp_proto.fields = {f_message_type, f_message_id, f_message_name, f_payload, f_valid, f_version, f_ipv6}

local ocpputil = require("ocpputil")

-- Multidimensional table to store loaded schemas
local areSchemasLoaded = false
local schemas_table = {}

-- as the responses do not contain the message name, but the id of request
-- and response is the same, we have to keep track of which id corresponds
-- to which message name.
-- According to:
-- OCPP-1.6J specification 4.2.2. CallResult
-- OCPP-2.0.1J specification 4.2.2. CallResult
-- OCPP-2.1J specification 4.2.2. CallResult
local msg_name_id_lut = {}

-- reload schemas when preferences are changed
function update_schemas()
    for idx, version in pairs(OCPP_JSON_VERSIONS) do
        print("*************************" .. version .. "*************************")
        schemas_table[version] = {}
        ocpputil.load_schema(ocpp_proto.prefs["schemas" .. version .. "j"], schemas_table[version])
    end
    print("************* Finished loading schemas **************")
    areSchemasLoaded = true
end

function ocpp_proto.prefs_changed()
    update_schemas()
end

-- Function to validate JSON against a schema
-- shall validate the payload with the schema_name of the given version
-- if the validation with the given proto_version succeeds => return true, "", ""
-- if the validation with the given proto_version fails => return false, expected_version_error, valid_other_versions
local function validate_json(payload, schema_name, expected_version)
    local status = {}
    local result = {}
    local success = {}
    local err = {}

    -- Handle expected version validation
    status[expected_version] = false
    err[expected_version] = ""
    status[expected_version], result[expected_version] = pcall(function()
        print("schema_name is: " .. schema_name)
        local key
        if (expected_version == "1.6") then
            key = schema_name:gsub("Request$", "")
        else
            key = schema_name
        end
        success[expected_version], err[expected_version] = ocpputil.validate_schema(payload, schemas_table[expected_version], key)
    end)
    if status[expected_version] and success[expected_version] then
        return true, "", ""
    end

    local expected_version_error
    if not status[expected_version] then
        expected_version_error = result[expected_version]
    else
        expected_version_error = err[expected_version]
    end

    print("Error in v" .. expected_version .. " validation: ", expected_version_error)

    -- Only if the expected version fails, try all other versions
    for idx, version in ipairs(OCPP_JSON_VERSIONS) do
        if version ~= expected_version then
            status[version] = false
            err[version] = ""
            status[version], result[version] = pcall(function()
                print("schema_name is: " .. schema_name)
                local key
                if (version == "1.6") then
                    key = schema_name:gsub("Request$", "")
                else
                    key = schema_name
                end
                success[version], err[version] = ocpputil.validate_schema(payload, schemas_table[version], key)
            end)
        end
    end

    -- pack the validated procotol versions in a string
    local valid_versions_str = ''
    for idx, version in ipairs(OCPP_JSON_VERSIONS) do
        if success[version] then
            if not (valid_versions_str == '') then
                valid_versions_str = valid_versions_str .. '/' .. version
            else
                valid_versions_str = version
            end
        end
    end

    return false, expected_version_error, valid_versions_str
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

-- Dissector function, common to all protocol versions
local function common_dissector(buffer, pinfo, tree, proto_version)
    if areSchemasLoaded == false then
        -- usually wireshark calls the prefs_changed() function on startup
        -- and hereby loads our schemas. However, somehow I don't trust
        -- that feature, so make sure the schemas are loaded here.
        update_schemas()
    end
    
    local length = buffer:len()
    local ipv6 = false
    if length == 0 then return end

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
    ocpputil.printLuaTable(json_data)
    print('\n\n')

    local full_message_name = "" -- Variable to hold the result

    if message_type == 2 then
        full_message_name = message_name:gsub('["]', '') .. "Request"
    elseif message_type == 3 then
        -- get the actual message name from our look-up-table
        full_message_name = msg_name_id_lut[message_id]:gsub('["]', '') .. "Response"
    end

    pinfo.cols.protocol = "OCPP " .. proto_version
    pinfo.cols.info = full_message_name
    local subtree
    local next = next
    if (next(schemas_table[proto_version]) == nil) then
        subtree = tree:add(ocpp_proto, buffer(), "OCPP v" .. proto_version .. " no schemas found, skipping schema validation")
        subtree:add_proto_expert_info(f_missing_schema_expert)
    else
        local is_valid, validation_error, other_versions = validate_json(json_data, full_message_name, proto_version)
        print(string.format("VALID?: %s", tostring(is_valid)))
        print(string.format("ERROR?: %s", tostring(validation_error)))
        print(string.format("OTHER VERSIONS?: %s", tostring(other_versions)))
        print('\n')

        if is_valid then
            -- Create the protocol tree
            subtree = tree:add(ocpp_proto, buffer(), "OCPP Protocol v" .. proto_version .. " Payload")

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
        else
            subtree = tree:add(ocpp_proto, buffer(), "OCPP v" .. proto_version .. " Non-Compliant Packet")
            subtree:add(ProtoField.string("ocpp" .. proto_version .. ".error", "Error"), buffer(), validation_error)
            subtree:add(f_valid, is_valid):set_hidden(true)
            if other_versions == "" then
                subtree:add_proto_expert_info(f_valid_expert)
            else
                subtree:add_proto_expert_info(f_wrong_version_expert):append_text(", but packet is valid in version(s): " .. other_versions)
            end
            if not ipv6 then
                subtree:add(f_ipv6, false):set_hidden(true)
                subtree:add_proto_expert_info(f_ipv6_expert)
            end
        end
    end
    subtree:add(f_version, proto_version):set_hidden(true)
    -- Always add the parsed JSON data
    if json_data then
        if not(message_type == 3) then
            payload_tree = subtree:add(f_payload, buffer(3 + #message_id + #message_name +2, buffer:len()-(3 + #message_id + #message_name +2)-1), "Payload")
        else
            payload_tree = subtree:add(f_payload, buffer(3 + #message_id + 1, buffer:len()-(3 + #message_id)-2), "Payload")
        end

        -- Process the JSON data
        add_key_value_pairs(payload_tree, json_data, "")
    else
        subtree:add(f_payload, buffer(#message_name + 2), "Invalid JSON")
    end

end

-- add one dissector function for each OCPP version listed in the array
for idx, version in pairs(OCPP_JSON_VERSIONS) do
    ocpp_proto_list[version].dissector = function(buffer, pinfo, tree)
        print("***** New packet with protocol version " .. version .. " *******")
        common_dissector(buffer, pinfo, tree, version)
    end
end

-- Register each dissector
local ws_protocol_table = DissectorTable.get("ws.protocol")
for idx, version in pairs(OCPP_JSON_VERSIONS) do
    ws_protocol_table:add("ocpp" .. version, ocpp_proto_list[version])
end
