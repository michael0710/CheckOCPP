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
local f_message_type = ProtoField.uint8("ocpp.message_type_id", "MessageTypeId", base.DEC)
local f_unique_id = ProtoField.string("ocpp.unique_id", "UniqueId")
local f_message_id = ProtoField.string("ocpp.message_id", "MessageId")
local f_action = ProtoField.string("ocpp.action", "Action")
local f_error_code = ProtoField.string("ocpp.error_code", "ErrorCode")
local f_error_description = ProtoField.string("ocpp.error_description", "ErrorDescription")
local f_payload = ProtoField.string("ocpp.payload", "Payload")
local f_error_details = ProtoField.string("ocpp.error_details", "ErrorDetails")
local f_valid = ProtoField.bool("ocpp.valid", "Valid?", base.NONE)
local f_version = ProtoField.string("ocpp.version", "Protocol version")
local f_error_info = ProtoField.string("ocpp.error_info", "Error Information") -- this field is not part of the protocol, it is used to display information about a malformed packet

local f_valid_expert = ProtoExpert.new("OCPP_non_compliant", "OCPP non-compliant packet", expert.group.MALFORMED, expert.severity.ERROR)
local f_messagetypeid_expert = ProtoExpert.new("OCPP_unknown_message_type_id", "Unknown MessageTypeId (expected range 2-4)", expert.group.MALFORMED, expert.severity.ERROR)
local f_missing_schema_expert = ProtoExpert.new("OCPP_no_schema_provided", "OCPP JSON-schemas missing, schema validation will be skipped", expert.group.REASSEMBLE, expert.severity.WARN)
local f_wrong_version_expert = ProtoExpert.new("OCPP_non_compliant_version", "OCPP non-compliant packet, but compliant with other OCPP version", expert.group.MALFORMED, expert.severity.ERROR)

ocpp_proto.experts = { f_valid_expert, f_messagetypeid_expert, f_missing_schema_expert, f_wrong_version_expert }
ocpp_proto.fields = {f_message_type, f_unique_id, f_message_id, f_action, f_error_code, f_error_description, f_payload, f_error_details, f_valid, f_version, f_error_info}

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
local action_name_id_lut = {}

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
            local nested_tree = tree:add(formatted_key, "")
            add_key_value_pairs(nested_tree, value, prefix .. "  ")
        else
            -- Otherwise, add the key-value pair
            tree:add(formatted_key, "\"" .. tostring(value) .. "\"")
        end
    end
end

local function dissect_common_call_callresult_send_parts(buffer, pinfo, subtree, proto_version, message_id, full_action_name, json_data_str, buffer_idx)
    pinfo.cols.info:prepend(full_action_name .. " ")

    print(string.format("Data: %s", tostring(json_data_str)))
    print('\n')

    if (json_data_str == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing Payload")
        return
    end

    -- Parse and display JSON if possible
    local json_data = ocpputil.jsonToLua(json_data_str)
    print('LUA Table:')
    ocpputil.printLuaTable(json_data)
    print('\n\n')

    local next = next
    if (next(schemas_table[proto_version]) == nil) then
        subtree:add_proto_expert_info(f_missing_schema_expert)
    else
        local is_valid, validation_error, other_versions = validate_json(json_data, full_action_name, proto_version)
        print(string.format("VALID?: %s", tostring(is_valid)))
        print(string.format("ERROR?: %s", tostring(validation_error)))
        print(string.format("OTHER VERSIONS?: %s", tostring(other_versions)))
        print('\n')

        subtree:add(f_valid, is_valid):set_hidden(true)
        if not(is_valid) then
            subtree:add(f_error_info, buffer(buffer_idx, #json_data_str), validation_error)
            if other_versions == "" then
                subtree:add_proto_expert_info(f_valid_expert)
            else
                subtree:add_proto_expert_info(f_wrong_version_expert):append_text(", but packet is valid in version(s): " .. other_versions)
            end
        end
    end
    -- Always add the parsed JSON data
    if json_data then
        payload_tree = subtree:add(f_payload, buffer(buffer_idx, #json_data_str), "")

        -- Process the JSON data
        add_key_value_pairs(payload_tree, json_data, "")
    else
        subtree:add(f_payload, buffer(buffer_idx, #json_data_str), "Invalid JSON")
    end
end

local function dissect_call_frame(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
    pinfo.cols.info = "[CALL]"

    local action_name = nil
    if (elements[3] ~= nil) then
        action_name = ocpputil.cleanElement(elements[3]:gsub('^["\'](.-)["\']$', '%1'))
        action_name_id_lut[message_id] = action_name
    end
    print(string.format("Action: %s", tostring(action_name)))
    if (action_name == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing Action")
        return
    end
    
    local full_action_name = action_name:gsub('["]', '') .. "Request"
    subtree:add(f_action, buffer(buffer_idx, #action_name), full_action_name)
    buffer_idx = buffer_idx + #action_name + 1

    local json_data_str = nil
    if (elements[4] ~= nil) then
        json_data_str = ocpputil.cleanElement(elements[4])
    end

    dissect_common_call_callresult_send_parts(buffer, pinfo, subtree, proto_version, message_id, full_action_name, json_data_str, buffer_idx)
end

local function dissect_callresult_frame(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
    pinfo.cols.info = "[CALLRESULT]"

    local full_action_name = action_name_id_lut[message_id]
    if full_action_name == nil then
        full_action_name = "Unknown Response"
        subtree:add(f_action, full_action_name):append_text(" (no action name matches given ID)")
        -- If we name it "Unknown Response" here, the validation will fail anyways, and so tha packet will
        -- be marked invalid later on
    else
        full_action_name = full_action_name:gsub('["]', '') .. "Response"
        subtree:add(f_action, full_action_name):append_text(" (implicit by ID)")
    end
    
    local json_data_str = nil
    if (elements[3] ~= nil) then
        json_data_str = ocpputil.cleanElement(elements[3])
    end
    
    dissect_common_call_callresult_send_parts(buffer, pinfo, subtree, proto_version, message_id, full_action_name, json_data_str, buffer_idx)
end

local function dissect_common_callerror_callresulterror_parts(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
    local error_code = nil
    if (elements[3] ~= nil) then
        error_code = ocpputil.cleanElement(elements[3]:gsub('^["\'](.-)["\']$', '%1'))
    end
    print(string.format("Error Code: %s", tostring(error_code)))
    if (error_code == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing ErrorCode")
        return
    end
    subtree:add(f_error_code, buffer(buffer_idx, #error_code), error_code)
    buffer_idx = buffer_idx + #error_code + 1

    local error_description = nil
    if (elements[4] ~= nil) then
        error_description = ocpputil.cleanElement(elements[4]:gsub('^["\'](.-)["\']$', '%1'))
    end
    print(string.format("Error Description: %s", tostring(error_description)))
    if (error_description == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing ErrorDescription")
        return
    end
    subtree:add(f_error_description, buffer(buffer_idx, #error_description), error_description)
    buffer_idx = buffer_idx + #error_description + 1

    local error_details = nil
    if (elements[5] ~= nil) then
        error_details = ocpputil.cleanElement(elements[5]:gsub('^["\'](.-)["\']$', '%1'))
    end
    print(string.format("Error Details: %s", tostring(error_details)))
    if (error_details == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing ErrorDetails")
        return
    end
    local error_details_json = ocpputil.jsonToLua(error_details)
    local error_details_tree = subtree:add(f_error_details, buffer(buffer_idx, #error_details))
    add_key_value_pairs(error_details_tree, error_details_json, "")
end

local function dissect_callerror_frame(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
    local full_action_name = action_name_id_lut[message_id]
    if full_action_name then
        pinfo.cols.info = full_action_name:gsub('["]', '') .. "Response [CALLERROR]"
    else
        pinfo.cols.info = "unknown message [CALLERROR]"
    end

    dissect_common_callerror_callresulterror_parts(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
end

local function dissect_callresulterror_frame(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
    local full_action_name = action_name_id_lut[message_id]
    if full_action_name then
        pinfo.cols.info = full_action_name:gsub('["]', '') .. "Response [CALLRESULTERROR]"
    else
        pinfo.cols.info = "unknown message [CALLRESULTERROR]"
    end

    dissect_common_callerror_callresulterror_parts(buffer, pinfo, subtree, proto_version, elements, message_id, buffer_idx)
end

local function dissect_send_frame()
    pinfo.cols.info = "[SEND]"

    local action_name = nil
    if (elements[3] ~= nil) then
        action_name = ocpputil.cleanElement(elements[3]:gsub('^["\'](.-)["\']$', '%1'))
        action_name_id_lut[message_id] = action_name
    end
    print(string.format("Action: %s", tostring(action_name)))
    if (action_name == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing Action")
        return
    end
    
    local full_action_name = action_name:gsub('["]', '')
    subtree:add(f_action, buffer(buffer_idx, #action_name), full_action_name)
    buffer_idx = buffer_idx + #action_name + 1

    local json_data_str = nil
    if (elements[4] ~= nil) then
        json_data_str = ocpputil.cleanElement(elements[4])
    end

    dissect_common_call_callresult_send_parts(buffer, pinfo, subtree, proto_version, message_id, full_action_name, json_data_str, buffer_idx)
end

local function dissect_ocpp_main_frame(buffer, pinfo, subtree, proto_version, payload)
    -- Extract elements from the JSON array
    local valid_frame, elements = ocpputil.parseJSONArray(payload)
    if not(valid_frame) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "no valid JSON frame")
        return
    end

    -- Extract MessageTypeId
    local message_type = tonumber(elements[1])
    print(string.format("Type: %s", tostring(message_type)))
    if (message_type == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing MessageTypeId")
        return
    elseif (proto_version ~= "2.1") and (message_type < 2) or (message_type > 4) then
        subtree:add_proto_expert_info(f_messagetypeid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "expected MessageTypeId in range 2-4, got " .. tostring(message_type))
        return
    elseif (proto_version == "2.1") and (message_type < 2) or (message_type > 6) then
        subtree:add_proto_expert_info(f_messagetypeid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "expected MessageTypeId in range 2-6, got " .. tostring(message_type))
        return
    end
    subtree:add(f_message_type, buffer(1, 1), message_type):append_text(" (2=Request, 3=Response, 4=Error)")

    -- Extract UniqueId
    local message_id = nil
    if (elements[2] ~= nil) then
        message_id = ocpputil.cleanElement(elements[2]:gsub('^["\'](.-)["\']$', '%1'))
    end
    print(string.format("ID: %s", tostring(message_id)))
    if (message_id == nil) then
        subtree:add_proto_expert_info(f_valid_expert):append_text(": invalid frame")
        subtree:add(f_valid, false):set_hidden(true)
        subtree:add(f_error_info, "missing MessageId")
        return
    end
    if (proto_version == "1.6") then
        subtree:add(f_unique_id, buffer(3, #message_id), message_id)
    else
        subtree:add(f_message_id, buffer(3, #message_id), message_id)
    end

    -- just a short list of constants that are not used elsewhere:
    local MSG_TYPE_CALL = 2
    local MSG_TYPE_CALLRESULT = 3
    local MSG_TYPE_CALLERROR = 4
    local MSG_TYPE_CALLRESULTERROR = 5
    local MSG_TYPE_SEND = 6
    
    if (message_type == MSG_TYPE_CALL) then
        dissect_call_frame(buffer, pinfo, subtree, proto_version, elements, message_id, 4 + #message_id)
    elseif (message_type == MSG_TYPE_CALLRESULT) then
        dissect_callresult_frame(buffer, pinfo, subtree, proto_version, elements, message_id, 4 + #message_id)
    elseif (message_type == MSG_TYPE_CALLERROR) then
        dissect_callerror_frame(buffer, pinfo, subtree, proto_version, elements, message_id, 4 + #message_id)
    elseif (proto_version == "2.1") and (message_type == MSG_TYPE_CALLRESULTERROR) then
        dissect_callresulterror_frame(buffer, pinfo, subtree, proto_version, elements, message_id, 4 + #message_id)
    elseif (proto_version == "2.1") and (message_type == MSG_TYPE_SEND) then
        dissect_send_frame()
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
    
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "OCPP " .. proto_version
    pinfo.cols.info = "invalid packet"
    local subtree = tree:add(ocpp_proto, buffer(), "OCPP Protocol v" .. proto_version)
    subtree:add(f_version, proto_version):set_hidden(true)
    print(pinfo.src)

    -- Convert buffer to a string
    local payload = buffer():string()

    dissect_ocpp_main_frame(buffer, pinfo, subtree, proto_version, payload)
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
