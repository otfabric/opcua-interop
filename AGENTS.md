# AGENTS.md — opcua-interop

## What this is

Independent OPC UA reference stacks (open62541, Eclipse Milo, async-opcua, UA-.NETStandard, node-opcua, opcua-asyncio) in containers behind one command-line contract, with deterministic fixtures, used as oracles by go-opcua and opcuactl. Nothing here depends on go-opcua, except `own/`, the one image of OT Fabric's own stack (`own/go-opcua/README.md`). Profile: **interoperability**.

## Organisation standards

This repository follows **otfabric/engineering policy 1.2**, profile **interoperability** (`.otfabric/policy.yaml`, mode `enforce`). Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Container commands, documents, exit codes | docs/CONTAINER_CONTRACT.md (`contract_version` in versions.yaml), schemas/ |
| What each stack can do | docs/CAPABILITIES.md, `print-capabilities` |
| Pins (upstream version, base image digests) | versions.yaml, checked by `make validate` |
| Fixtures, PubSub configurations, test PKI | fixtures/, certs/, docs/FIXTURES.md |
| Expected deviations of the stacks | tests/known-bugs.tsv |
| Results | docs/COMPATIBILITY.md |
| What this repository must and must not do | REQUIREMENTS.md |
| What is done and what is next | PLAN.md |

## Hard rules

1. Nothing floats: upstream versions and base images by digest. `make validate` must pass.
2. Skips and known differences are never counted as passes.
3. Features a stack lacks are declared in `print-capabilities` and refused with the contract's exit code, never faked.
4. Contract changes bump `contract_version` and reach docs/CONTAINER_CONTRACT.md and every adapter in the same change.
5. Every adapter reports the release version; `make check-release VERSION=vX.Y.Z` lists what differs. The release tag equals `interop_version`.
6. Licences: every redistributed component in THIRD_PARTY_NOTICES.md.
7. `certs/generate.sh` and `certs/test-pki` stay at that path: consumers' workflows use them.
8. `own/` is the one place that builds a library under test (`own/go-opcua/README.md`). Its image is not a reference and is not in a release. It declares a subset of the contract, so a contract change need not extend it.

## Commands

| When you change… | Run |
|---|---|
| anything | `make validate lint` |
| an adapter | `make image-<adapter> smoke-<adapter>` |
| cross-stack behaviour | `make interop` |
| PubSub | `make pubsub` |
| documents or the contract | `make documents` |
| everything | `make ci` |
| a release | `make check-release VERSION=vX.Y.Z` |

## Git and releases

Branches and PRs. Do not push to `main`, push tags, publish images or run release workflows unless the maintainer asks in the session.
