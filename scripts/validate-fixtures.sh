#!/usr/bin/env bash
# Validate all fixture files against the JSON Schema.
# Requires: check-jsonschema (pip install check-jsonschema) or ajv-cli (npm install -g ajv-cli)
#
# Exits 0 if all fixtures are valid, nonzero otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA="${REPO_ROOT}/fixtures/schema/opcua-fixture.schema.json"

if [[ ! -f "${SCHEMA}" ]]; then
    echo "Error: fixture schema not found at ${SCHEMA}" >&2
    exit 1
fi

FIXTURES=()
while IFS= read -r -d '' f; do
    FIXTURES+=("$f")
done < <(find "${REPO_ROOT}/fixtures" -name "fixture.json" -print0 | sort -z)

if [[ ${#FIXTURES[@]} -eq 0 ]]; then
    echo "No fixture files found." >&2
    exit 0
fi

echo "Validating ${#FIXTURES[@]} fixture(s) against schema..."

TOOL=""
if command -v check-jsonschema &>/dev/null; then
    TOOL="check-jsonschema"
elif command -v ajv &>/dev/null; then
    TOOL="ajv"
else
    echo "Warning: no JSON Schema validator found. Install check-jsonschema or ajv-cli." >&2
    echo "  pip install check-jsonschema" >&2
    echo "  npm install -g ajv-cli" >&2
    echo "Skipping fixture validation." >&2
    exit 0
fi

FAILED=0
for fixture in "${FIXTURES[@]}"; do
    rel="${fixture#${REPO_ROOT}/}"
    if [[ "${TOOL}" == "check-jsonschema" ]]; then
        if check-jsonschema --schemafile "${SCHEMA}" "${fixture}" 2>&1; then
            echo "  OK  ${rel}"
        else
            echo "  FAIL ${rel}" >&2
            FAILED=$((FAILED + 1))
        fi
    elif [[ "${TOOL}" == "ajv" ]]; then
        if ajv validate -s "${SCHEMA}" -d "${fixture}" --spec=draft2020 2>&1; then
            echo "  OK  ${rel}"
        else
            echo "  FAIL ${rel}" >&2
            FAILED=$((FAILED + 1))
        fi
    fi
done

if [[ "${FAILED}" -gt 0 ]]; then
    echo "${FAILED} fixture(s) failed validation." >&2
    exit 1
fi

echo "All fixtures valid."
