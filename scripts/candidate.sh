#!/usr/bin/env bash
# Builds one adapter at a candidate upstream release and tests it: unit/self
# tests where the adapter has a `test` command, then the smoke (open62541 also
# the PubSub smoke). The Upstream workflow (.github/workflows/upstream.yml)
# runs it for every stack whose pin is behind the latest release
# (scripts/latest-upstream.py).
#
# Usage:
#   candidate.sh <open62541|milo|async-opcua|dotnet|dotnet-gds|node-opcua|asyncua> <version>
#
# The image is tagged opcua-interop-<adapter>:candidate. Pins are not changed:
# async-opcua, node-opcua and asyncua pin exactly and build from a lock file,
# so their manifest and lock file (async-opcua: also STACK_VERSION in
# src/common.rs) are pointed at the candidate for the build and restored on
# exit.
#
# Exit codes:
#   0  — built and every test passed
#   1  — build or a test failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

ADAPTER="${1:?Usage: candidate.sh <adapter> <version>}"
VERSION="${2:?Usage: candidate.sh <adapter> <version>}"
IMAGE="opcua-interop-${ADAPTER}:candidate"

log() { echo "[candidate] $*" >&2; }

# Files edited for the build; their originals are put back on exit.
BACKUP="$(mktemp -d)"
EDITED=()
restore() {
    local f
    for f in "${EDITED[@]+"${EDITED[@]}"}"; do
        cp "${BACKUP}/$(echo "${f}" | tr / _)" "${f}"
    done
    rm -rf "${BACKUP}"
}
trap restore EXIT
edit() {
    local f
    for f in "$@"; do
        cp "${f}" "${BACKUP}/$(echo "${f}" | tr / _)"
        EDITED+=("${f}")
    done
}

build() {
    log "Building ${IMAGE}..."
    docker build --tag "${IMAGE}" --file "${ADAPTER}/Dockerfile" "$@" "${ADAPTER}/"
}

self_test() {
    log "Running the ${ADAPTER} test command..."
    docker run --rm -v "${REPO_ROOT}/fixtures:/fixtures:ro" "${IMAGE}" test
}

case "${ADAPTER}" in
    open62541)
        build --build-arg "OPEN62541_COMMIT=${VERSION}"
        scripts/smoke.sh open62541 "${IMAGE}"
        scripts/pubsub-smoke.sh "${IMAGE}"
        ;;
    milo)
        build --build-arg "MILO_VERSION=${VERSION}"
        scripts/smoke.sh milo "${IMAGE}"
        ;;
    async-opcua)
        # The pin is exact (=X.Y.Z) and the build is --locked.
        edit async-opcua/Cargo.toml async-opcua/Cargo.lock async-opcua/src/common.rs
        sed -i.orig -E "s/^async-opcua = \{ version = \"=[0-9.]+\"/async-opcua = { version = \"=${VERSION}\"/" async-opcua/Cargo.toml
        sed -i.orig -E "s/^pub const STACK_VERSION: &str = \"[0-9.]+\";/pub const STACK_VERSION: \&str = \"${VERSION}\";/" async-opcua/src/common.rs
        rm -f async-opcua/Cargo.toml.orig async-opcua/src/common.rs.orig
        cargo update --manifest-path async-opcua/Cargo.toml -p async-opcua
        git diff --stat -- async-opcua
        build
        scripts/smoke.sh async-opcua "${IMAGE}"
        ;;
    dotnet | dotnet-gds)
        build --build-arg "OPCUA_VERSION=${VERSION}"
        self_test
        scripts/smoke.sh "${ADAPTER}" "${IMAGE}"
        ;;
    node-opcua)
        # The pin is exact and the build is `npm ci`: node-opcua-types moves
        # with node-opcua.
        edit node-opcua/package.json node-opcua/package-lock.json
        types=$(npm view "node-opcua@${VERSION}" dependencies.node-opcua-types)
        (cd node-opcua && npm install --package-lock-only --save-exact --no-audit --no-fund \
            "node-opcua@${VERSION}" "node-opcua-types@${types}")
        git diff --stat -- node-opcua
        build
        scripts/smoke.sh node-opcua "${IMAGE}"
        ;;
    asyncua)
        # The pin is exact (asyncua==X.Y.Z) and the lock carries hashes. The
        # image build runs the unit tests.
        edit asyncua/requirements.in asyncua/requirements.txt
        sed -i.orig -E "s/^asyncua==[0-9.]+$/asyncua==${VERSION}/" asyncua/requirements.in
        rm -f asyncua/requirements.in.orig
        command -v uv >/dev/null 2>&1 || pip install --quiet uv
        (cd asyncua && uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt)
        git diff --stat -- asyncua
        build
        self_test
        scripts/smoke.sh asyncua "${IMAGE}"
        ;;
    *)
        echo "Unknown adapter: ${ADAPTER}. Use open62541, milo, async-opcua, dotnet, dotnet-gds, node-opcua or asyncua." >&2
        exit 1
        ;;
esac
