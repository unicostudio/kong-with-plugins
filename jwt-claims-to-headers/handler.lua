local cjson = require "cjson"

local plugin = {
  PRIORITY = 900,
  VERSION = "0.1.0",
}

local function get_jwt_token()
  local authorization_header = kong.request.get_header("authorization")
  if authorization_header then
    local token = authorization_header:match("Bearer%s+(.+)")
    if token then
      return token
    end
  end
  return nil
end

local function decode_jwt_payload(token)
  local segments = {}
  for segment in token:gmatch("[^%.]+") do
    table.insert(segments, segment)
  end
  
  if #segments < 2 then
    return nil
  end
  
  -- Decode base64url payload (second segment)
  local payload_b64 = segments[2]
  
  -- Add padding if needed
  local padding = 4 - (#payload_b64 % 4)
  if padding < 4 then
    payload_b64 = payload_b64 .. string.rep("=", padding)
  end
  
  -- Replace base64url chars with base64 chars
  payload_b64 = payload_b64:gsub("-", "+"):gsub("_", "/")
  
  local payload_json = ngx.decode_base64(payload_b64)
  if not payload_json then
    return nil
  end
  
  local success, payload = pcall(cjson.decode, payload_json)
  if not success then
    return nil
  end
  
  return payload
end

local function is_excluded_claim(claim_name, excluded_claims)
  for _, excluded in ipairs(excluded_claims) do
    if claim_name == excluded then
      return true
    end
  end
  return false
end

function plugin:access(conf)
  local token = get_jwt_token()
  if not token then
    kong.log.debug("No JWT token found")
    return
  end
  
  local payload = decode_jwt_payload(token)
  if not payload then
    kong.log.warn("Failed to decode JWT payload")
    return
  end
  
  -- Set headers from claims
  for claim_name, claim_value in pairs(payload) do
    if not is_excluded_claim(claim_name, conf.claims_to_exclude) then
      local header_name = conf.header_prefix .. claim_name:upper()
      local header_value = type(claim_value) == "table" and cjson.encode(claim_value) or tostring(claim_value)
      kong.service.request.set_header(header_name, header_value)
    end
  end
  
  -- Include raw token if requested
  if conf.include_raw_token then
    kong.service.request.set_header(conf.header_prefix .. "RAW-TOKEN", token)
  end
end

return plugin