# node-opcua (TypeScript / Node.js) adapter — multi-stage build.
# Build from the node-opcua/ directory:
#   docker build -f node-opcua/Dockerfile -t opcua-interop-node-opcua:local node-opcua/
#
# The stack is the node-opcua package from npm, pinned exactly in
# package.json (2.187.12) and package-lock.json (`npm ci`). node-opcua is pure
# JavaScript on Node.js' OpenSSL crypto, so the same Dockerfile builds
# natively for linux/amd64 and linux/arm64 (the node image is multi-arch; the
# pin is its multi-arch index digest).

ARG NODE_IMAGE=node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

# ---------------------------------------------------------------------------
# Stage 1 — compile the TypeScript adapter and run its unit tests
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# The unit tests (`npm test`: node --test, src/*.test.ts) run in the build: an image is
# only produced when they pass. `docker run <image> test` checks the mounted
# fixtures.
COPY tsconfig.json ./
COPY src/ src/
COPY testdata/ testdata/
RUN npm run build \
    && npm test \
    && rm dist/*.test.js

# ---------------------------------------------------------------------------
# Stage 2 — production dependencies only (lockfile-exact)
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS deps

WORKDIR /deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force \
    && find node_modules \( -name '*.map' -o -name '*.d.ts' -o -name '*.d.ts.map' -o -name '*.tsbuildinfo' \) -type f -delete

# ---------------------------------------------------------------------------
# Stage 3 — runtime
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS runtime

ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /deps/node_modules ./node_modules
COPY --from=build /build/dist ./dist
COPY package.json ./

# npm / corepack / yarn are not needed at runtime. The adapter runs as the
# image's unprivileged `node` user (uid 1000); /run/opcua-interop is writable
# for the ready file and the default PKI.
RUN rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && mkdir -p /run/opcua-interop/pki /fixtures \
    && chown -R node:node /run/opcua-interop

ENV OPCUA_FIXTURE=/fixtures/fixture.json

USER node
EXPOSE 4840

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=30 \
  CMD test -f /run/opcua-interop/ready

ENTRYPOINT ["node", "/app/dist/main.js"]
CMD ["server"]
