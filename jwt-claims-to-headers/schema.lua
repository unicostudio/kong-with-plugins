local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-claims-to-headers",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { header_prefix = { type = "string", default = "X-JWT-" } },
          { claims_to_exclude = { 
              type = "array", 
              elements = { type = "string" },
              default = { "iat", "exp", "nbf", "jti" }
          } },
          { include_raw_token = { type = "boolean", default = false } }
        },
      },
    },
  },
}