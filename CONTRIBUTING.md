# Contributing to opcua-interop

## Ground rules

- **Nothing here may know about a library under test.** No imports, no build steps, no expectations, no names from `go-opcua` or any other consumer under `adapters/`, `fixtures/`, `schemas/`, `scripts/`, `tests/` or in the top-level `Makefile` and `compose.yaml`; CI greps for it, documentation aside. See [REQUIREMENTS.md](REQUIREMENTS.md) R1, and `own/` for the one exception.
- **The contract is the product.** Adapters differ inside; their commands, documents and exit codes are identical. A change to [docs/CONTAINER_CONTRACT.md](docs/CONTAINER_CONTRACT.md) or [docs/FIXTURES.md](docs/FIXTURES.md) lands in every adapter that declares the feature in the same change.
- **Declare only what is tested.** A capability is declared when the self-tests or the image's own tests exercise it for that adapter.
- **Pin everything.** Upstreams by exact version, base images by digest, all mirrored in [versions.yaml](versions.yaml).

## Setup

Docker (with buildx), `jq`, GNU make, `openssl` >= 1.1 and Python 3. Nothing else: compilers and SDKs run inside the image builds.

```sh
make ci     # validate, lint, build, smoke, cross-stack self-test, document schemas
```

Run `make` for all targets.

## Changing an adapter

1. Edit under `adapters/<adapter>/`. The build context is the repository root, so a new `COPY` names the whole path; exclusions are in the root `.dockerignore`.
2. `make image-<adapter> smoke-<adapter>`.
3. `make interop`. If two stacks disagree, find out which one is right by the standard before touching the expectation.
4. If behaviour visible to consumers changed, update the contract or fixture documentation in the same change.

## Moving an upstream pin

1. Change the pin in the build files and in `versions.yaml`; `scripts/check-versions.sh` must pass.
2. `make ci`.
3. Record the new version, and anything it changed, in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [RELEASE.md](RELEASE.md).

The rule is the latest upstream release, also when it has a bug: list the bug in [tests/known-bugs.tsv](tests/known-bugs.tsv) and describe it in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md), rather than pinning an older release. When a run reports that a known bug no longer reproduces, remove its entry.

The **Upstream** workflow does this probe every day for every stack whose pin is behind; `scripts/latest-upstream.py <component>` prints pin and latest, and `make candidate-<adapter> CANDIDATE=<version>` runs the same thing locally.

## Registries and retries

CI does not pull from Docker Hub: its anonymous rate limit and its token service fail too often on shared runners. The workflows set `BASE_REGISTRY=mirror.gcr.io/library` (base images, which the Dockerfiles pin by digest, so the mirror cannot change what is built) and `TOOLS_REGISTRY=mirror.gcr.io` (BuildKit, QEMU handlers, shellcheck). Locally both default to Docker Hub. The .NET base images come from `mcr.microsoft.com`.

Every command that talks to a registry runs through `scripts/retry.sh`, which repeats it with a growing delay when the output shows a rate limit, a 5xx or a timeout, and returns any other failure at once. `make publish-arch`, `make publish-manifest` and `make digests` are what the release workflow calls in place of the Docker push actions.

Both architectures are built and self-tested natively, on an amd64 and an arm64 runner; nothing in CI runs under emulation. `make buildx-setup` and `make buildx` remain for checking the other architecture from one machine.

## Adding a client operation or a server behaviour

1. Specify it first: the operation, its flags, when it succeeds and its result fields in the contract; the server behaviour in [docs/FIXTURES.md](docs/FIXTURES.md).
2. Implement it in the adapters whose stack can do it; the others refuse it with exit code 2.
3. Add cases to [tests/cases.tsv](tests/cases.tsv) (or [tests/secure-cases.tsv](tests/secure-cases.tsv), [tests/codec-cases.tsv](tests/codec-cases.tsv)) with the expected exit code, a `jq` expectation on the document and the features it needs. A check that needs more than one client lives in `scripts/features.sh`.
4. Add the feature to the capability documents, [docs/CAPABILITIES.md](docs/CAPABILITIES.md) and [COVERAGE.md](COVERAGE.md).
5. Extend the schemas in `schemas/` if documents gained fields.

Additive changes bump the contract's minor version; anything a consumer could break on bumps the major version.

## Adding a fixture

See [docs/FIXTURES.md](docs/FIXTURES.md#adding-a-fixture).

## Adding an adapter

1. Evaluate the upstream: does it build from a pinned source on both architectures, which roles does it provide, what is its licence, and is its protocol engine its own? Write the answers into [PLAN.md](PLAN.md) before writing code.
2. Create `adapters/<name>/` with a Dockerfile built from the repository root, following the existing ones: pinned build stage, minimal runtime stage, non-root user, `/fixtures`, `/licenses`, the readiness file, the health check.
3. Implement the contract. What the upstream cannot do is left out of `print-capabilities`, and the cases that need it name it in their `needs` column: never fake a behaviour the library does not have.
4. `scripts/smoke.sh <name>` must pass, then `scripts/interop.sh open62541 milo <name>`.
5. Add it to `ADAPTERS` in the Makefile, to the workflows, `versions.yaml`, `scripts/check-versions.sh`, `scripts/check-release.sh`, the test PKI, the notices and the documentation tables.

Do not build a shared adapter framework. The adapters share a contract, not code.

## Style

- Shell: `bash`, `set -uo pipefail`, shellcheck-clean (`make lint`). No associative arrays or other bash 4+ features in code paths macOS's `/bin/bash` could run.
- Documentation states what was verified. If something is assumed or untested, say so.

## License

By contributing you agree that your contributions are licensed under the MIT license of the repository.
