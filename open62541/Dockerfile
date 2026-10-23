# open62541 C adapter — multi-stage build.
# Build from the open62541/ directory:
#   docker build -f open62541/Dockerfile -t opcua-interop-open62541:local open62541/

# ---------------------------------------------------------------------------
# Stage 1 — build open62541 amalgam from source
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS open62541-build

ARG OPEN62541_COMMIT=v1.5.9
ARG OPEN62541_REPO=https://github.com/open62541/open62541

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      cmake \
      git \
      libssl-dev \
      python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${OPEN62541_COMMIT}" "${OPEN62541_REPO}" open62541 \
    && cd open62541 \
    && git submodule update --init --depth 1

# Source preparation before the amalgamation is generated (both scripts only
# touch the exact v1.5.9 code and print a warning for anything else):
#  * inline_mqtt.py — MQTT (UA_ENABLE_MQTT) pulls the MQTT-C submodule into
#    arch/common/eventloop_mqtt.c with two quoted #include lines, which
#    tools/amalgamate.py drops; inline them so the amalgamation is complete.
#  * backport_json_reader.py — v1.5.9 DataSetReaders reject every JSON
#    NetworkMessage (an unimplemented TODO in UA_DataSetReader_checkIdentifier);
#    apply the PublisherId / DataSetWriterId matching of upstream master.
COPY amalgam/inline_mqtt.py amalgam/backport_json_reader.py /src/prepare/
RUN python3 /src/prepare/inline_mqtt.py /src/open62541 \
    && python3 /src/prepare/backport_json_reader.py /src/open62541

# Only the amalgamation target is built: the adapter compiles open62541.c itself,
# and with UA_ENABLE_AMALGAMATION + mDNS (mdnsd) the non-amalgamated object
# library of v1.5.9 does not compile (ua_discovery_mdns.c skips the xht.h /
# sdtxt.h includes under UA_ENABLE_AMALGAMATION).
#
# PubSub (Part 14): UADP + JSON NetworkMessages over opc.udp:// and mqtt://
# (MQTT-C), the PubSub information model with its configuration methods, the
# Security Key Service (GetSecurityKeys / SetSecurityKeys, SKS pull client;
# AddSecurityGroup is bound by the adapter) and the PubSubConfiguration file
# loader. The PubSub-Aes128/256-CTR message
# security policies of v1.5.9 only exist for mbedTLS; the adapter carries an
# OpenSSL implementation of them (src/pubsub_security.c).
WORKDIR /src/open62541/build
RUN cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_ENABLE_AMALGAMATION=ON \
      -DUA_NAMESPACE_ZERO=FULL \
      -DBUILD_SHARED_LIBS=OFF \
      -DUA_MULTITHREADING=0 \
      -DUA_BUILD_EXAMPLES=OFF \
      -DUA_BUILD_UNIT_TESTS=OFF \
      -DUA_ENABLE_ENCRYPTION=OPENSSL \
      -DUA_ENABLE_HISTORIZING=ON \
      -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=ON \
      -DUA_ENABLE_DISCOVERY=ON \
      -DUA_ENABLE_DISCOVERY_MULTICAST=MDNSD \
      -DUA_ENABLE_JSON_ENCODING=ON \
      -DUA_ENABLE_XML_ENCODING=ON \
      -DUA_ENABLE_PUBSUB=ON \
      -DUA_ENABLE_PUBSUB_INFORMATIONMODEL=ON \
      -DUA_ENABLE_PUBSUB_FILE_CONFIG=ON \
      -DUA_ENABLE_PUBSUB_SKS=ON \
      -DUA_ENABLE_MQTT=ON \
    && cmake --build . --target open62541-amalgamation -- -j"$(nproc)"

# ---------------------------------------------------------------------------
# Stage 2 — compile the adapter
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS adapter-build

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      libcjson-dev \
      libssl-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy open62541 amalgam
COPY --from=open62541-build /src/open62541/build/open62541.h /opt/open62541/include/open62541.h
COPY --from=open62541-build /src/open62541/build/open62541.c /opt/open62541/src/open62541.c

# Compile the amalgamation once into a static library. This layer is cached
# until the open62541 pin / build options (or amalgam/CMakeLists.txt) change.
COPY amalgam/ /src/amalgam/
WORKDIR /src/amalgam/build
RUN cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_AMALGAM_INCLUDE=/opt/open62541/include \
      -DUA_AMALGAM_SOURCE=/opt/open62541/src/open62541.c \
    && cmake --build . -- -j"$(nproc)" \
    && cmake --install . --prefix /opt/open62541

# Copy adapter source
COPY . /src/adapter

WORKDIR /src/adapter/build
RUN cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_AMALGAM_INCLUDE=/opt/open62541/include \
      -DUA_AMALGAM_LIBRARY=/opt/open62541/lib/libopen62541.a \
    && cmake --build . -- -j"$(nproc)" \
    && cmake --install . --prefix /opt/opcua-interop

# ---------------------------------------------------------------------------
# Stage 3 — minimal runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      libcjson1 \
      libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/opcua \
         --shell /usr/sbin/nologin opcua

COPY --from=adapter-build /opt/opcua-interop/bin/opcua-interop-open62541 \
       /usr/local/bin/opcua-interop-open62541

RUN mkdir -p /run/opcua-interop /fixtures \
    && chown opcua:opcua /run/opcua-interop

ENV OPCUA_FIXTURE=/fixtures/fixture.json \
    OPCUA_PORT=4840 \
    OPCUA_ENDPOINT_PATH=/opcua-interop \
    OPCUA_LOG_LEVEL=info \
    OPCUA_READY_FILE=/run/opcua-interop/ready \
    OPCUA_PKI_DIR=/run/opcua-interop/pki \
    OPCUA_TRUST_MODE=none

USER opcua
EXPOSE 4840

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=30 \
  CMD test -f /run/opcua-interop/ready

ENTRYPOINT ["/usr/local/bin/opcua-interop-open62541"]
CMD ["server"]
