#!/usr/bin/env bash
# Builds one adapter at a candidate upstream release and tests it like a
# release: the smoke test (with its `test` command; open62541 also the PubSub
# self-test), then the cross-stack self-test against the pinned open62541 and
# Milo. The Upstream workflow (.github/workflows/upstream.yml) runs it, through
# make candidate-<adapter>, for every stack whose pin is behind the latest
# release (scripts/latest-upstream.py).
#
# Usage:
#   candidate.sh <open62541|milo|async-opcua|dotnet|dotnet-gds|node-opcua|asyncua> <version>
#
# The image is tagged ghcr.io/otfabric/opcua-interop-<adapter>:candidate. Pins are not changed:
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
UPSTREAM="${2:?Usage: candidate.sh <adapter> <version>}"
REGISTRY="${REGISTRY:-ghcr.io/otfabric}"
BASE_REGISTRY="${BASE_REGISTRY:-docker.io/library}"
IMAGE="${REGISTRY}/opcua-interop-${ADAPTER}:candidate"

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
    scripts/retry.sh docker build --build-arg "BASE_REGISTRY=${BASE_REGISTRY}" --tag "${IMAGE}" --file "adapters/${ADAPTER}/Dockerfile" "$@" .
}

# The pinned stacks it is tested against, tagged like the candidate.
peers() {
    local peer
    for peer in open62541 milo; do
        [[ "${peer}" != "${ADAPTER}" ]] || continue
        make --no-print-directory "image-${peer}" VERSION=dev
        docker tag "${REGISTRY}/opcua-interop-${peer}:dev" "${REGISTRY}/opcua-interop-${peer}:candidate"
    done
}

self_test() {
    VERSION=candidate scripts/smoke.sh "${ADAPTER}"
    if [[ "${ADAPTER}" == dotnet-gds ]]; then return; fi
    peers
    local others=(open62541 milo) list=("${ADAPTER}") peer
    for peer in "${others[@]}"; do
        [[ "${peer}" == "${ADAPTER}" ]] || list+=("${peer}")
    done
    VERSION=candidate scripts/interop.sh "${list[@]}"
}

case "${ADAPTER}" in
    open62541)
        build --build-arg "OPEN62541_COMMIT=${UPSTREAM}"
        self_test
        VERSION=candidate scripts/pubsub-smoke.sh open62541
        ;;
    milo)
        build --build-arg "MILO_VERSION=${UPSTREAM}"
        self_test
        ;;
    async-opcua)
        # The pin is exact (=X.Y.Z) and the build is --locked.
        edit adapters/async-opcua/Cargo.toml adapters/async-opcua/Cargo.lock adapters/async-opcua/src/common.rs
        sed -i.orig -E "s/^async-opcua = \{ version = \"=[0-9.]+\"/async-opcua = { version = \"=${UPSTREAM}\"/" adapters/async-opcua/Cargo.toml
        sed -i.orig -E "s/^pub const STACK_VERSION: &str = \"[0-9.]+\";/pub const STACK_VERSION: \&str = \"${UPSTREAM}\";/" adapters/async-opcua/src/common.rs
        rm -f adapters/async-opcua/Cargo.toml.orig adapters/async-opcua/src/common.rs.orig
        cargo update --manifest-path adapters/async-opcua/Cargo.toml -p async-opcua
        git diff --stat -- adapters/async-opcua
        build
        self_test
        ;;
    dotnet | dotnet-gds)
        build --build-arg "OPCUA_VERSION=${UPSTREAM}"
        self_test
        ;;
    node-opcua)
        # The pin is exact and the build is `npm ci`: every node-opcua-* package
        # moves with node-opcua, to the version node-opcua depends on
        # (node-opcua-types) or else to the same release
        # (node-opcua-server-configuration). A package left behind puts a
        # second node-opcua-server in the tree and the build fails.
        edit adapters/node-opcua/package.json adapters/node-opcua/package-lock.json
        packages=("node-opcua@${UPSTREAM}")
        for pkg in $(jq -r '.dependencies | keys[] | select(startswith("node-opcua-"))' adapters/node-opcua/package.json); do
            version=$(npm view "node-opcua@${UPSTREAM}" "dependencies.${pkg}")
            packages+=("${pkg}@${version:-${UPSTREAM}}")
        done
        log "Pointing adapters/node-opcua/package.json at: ${packages[*]}"
        (cd adapters/node-opcua && npm install --package-lock-only --save-exact --no-audit --no-fund "${packages[@]}")
        git diff --stat -- adapters/node-opcua
        build
        self_test
        ;;
    asyncua)
        # The pin is exact (asyncua==X.Y.Z) and the lock carries hashes. The
        # image build runs the unit tests.
        edit adapters/asyncua/requirements.in adapters/asyncua/requirements.txt
        sed -i.orig -E "s/^asyncua==[0-9.]+$/asyncua==${UPSTREAM}/" adapters/asyncua/requirements.in
        rm -f adapters/asyncua/requirements.in.orig
        command -v uv >/dev/null 2>&1 || pip install --quiet uv
        (cd adapters/asyncua && uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt)
        git diff --stat -- adapters/asyncua
        build
        self_test
        ;;
    *)
        echo "Unknown adapter: ${ADAPTER}. Use open62541, milo, async-opcua, dotnet, dotnet-gds, node-opcua or asyncua." >&2
        exit 1
        ;;
esac
