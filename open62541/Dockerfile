# open62541 C adapter — multi-stage build.
# Build from the open62541/ directory:
#   docker build -f open62541/Dockerfile -t opcua-interop-open62541:local open62541/

# ---------------------------------------------------------------------------
# Stage 1 — build open62541 amalgam from source
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS open62541-build

ARG OPEN62541_COMMIT=v1.3.9
ARG OPEN62541_REPO=https://github.com/open62541/open62541

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      cmake \
      git \
      python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${OPEN62541_COMMIT}" "${OPEN62541_REPO}" open62541 \
    && cd open62541 \
    && git submodule update --init --depth 1

WORKDIR /src/open62541/build
RUN cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_ENABLE_AMALGAMATION=ON \
      -DUA_NAMESPACE_ZERO=FULL \
      -DBUILD_SHARED_LIBS=OFF \
      -DUA_MULTITHREADING=0 \
      -DUA_BUILD_EXAMPLES=OFF \
      -DUA_BUILD_UNIT_TESTS=OFF \
    && cmake --build . -- -j"$(nproc)"

# ---------------------------------------------------------------------------
# Stage 2 — compile the adapter
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS adapter-build

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      libcjson-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy open62541 amalgam
COPY --from=open62541-build /src/open62541/build/open62541.h /opt/open62541/include/open62541.h
COPY --from=open62541-build /src/open62541/build/open62541.c /opt/open62541/src/open62541.c

    # Copy adapter source
COPY . /src/adapter

WORKDIR /src/adapter/build
RUN cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_AMALGAM_INCLUDE=/opt/open62541/include \
      -DUA_AMALGAM_SOURCE=/opt/open62541/src/open62541.c \
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

ENTRYPOINT ["/usr/local/bin/opcua-interop-open62541", "server"]
