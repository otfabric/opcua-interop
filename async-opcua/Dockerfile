# async-opcua (Rust) adapter — multi-stage build.
# Build from the async-opcua/ directory:
#   docker build -f async-opcua/Dockerfile -t opcua-interop-async-opcua:local async-opcua/
#
# The stack is the async-opcua crate from crates.io, pinned in Cargo.toml
# (=0.19.0) and Cargo.lock. Pure-Rust crypto (RustCrypto): no OpenSSL, so the
# same Dockerfile builds natively for linux/amd64 and linux/arm64.

ARG RUST_IMAGE=rust:1.99.0-slim-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-20261005-slim

# ---------------------------------------------------------------------------
# Stage 1 — compile (dependencies in their own layer)
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && cargo test --release --locked --no-run \
    && rm -rf src target/release/opcua-interop-async-opcua* target/release/deps/opcua_interop_async_opcua*

# The unit tests (`cargo test`) run in the build: an image is only produced
# when they pass. `docker run <image> test` checks the mounted fixtures.
COPY src/ src/
COPY testdata/ testdata/
RUN cargo test --release --locked \
    && cargo build --release --locked \
    && install -D target/release/opcua-interop-async-opcua /out/opcua-interop-async-opcua

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

RUN useradd --system --uid 10001 --create-home --home-dir /home/opcua \
      --shell /usr/sbin/nologin opcua \
    && mkdir -p /run/opcua-interop /fixtures \
    && chown opcua:opcua /run/opcua-interop

COPY --from=build /out/opcua-interop-async-opcua /usr/local/bin/opcua-interop-async-opcua

ENV OPCUA_FIXTURE=/fixtures/fixture.json

USER opcua
EXPOSE 4840

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=30 \
  CMD test -f /run/opcua-interop/ready

ENTRYPOINT ["/usr/local/bin/opcua-interop-async-opcua"]
CMD ["server"]
