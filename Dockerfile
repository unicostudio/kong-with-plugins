FROM kong:latest

USER root

# Install dependencies required by LuaRocks
RUN apt-get update && \
    apt-get install -y zip unzip wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install the plugin
RUN luarocks install kong-plugin-jwt-claims-to-headers

ENV KONG_PLUGINS=bundled,jwt-claims-to-headers

USER kong
