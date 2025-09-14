FROM kong:latest

USER root

# Create plugin directory
COPY jwt-claims-to-headers /usr/local/share/lua/5.1/kong/plugins/jwt-claims-to-headers

USER kong

ENV KONG_PLUGINS=bundled,jwt-claims-to-headers
