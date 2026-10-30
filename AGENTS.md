# AGENTS.md — opcua-interop

## What this is

Independent OPC UA reference stacks (open62541, Eclipse Milo, async-opcua, UA-.NETStandard, node-opcua, opcua-asyncio) as containers behind one command contract, with deterministic fixtures, used as oracles by go-opcua and opcuactl. Profile: **interoperability**.

## Organisation standards

This repository follows **otfabric/engineering policy 1.0**, profile **interoperability** (`.otfabric/policy.yaml`, mode `baseline`). Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Client command contract | docs/CLIENT_CONTRACT.md |
| Result and capability documents | schemas/ |
| Pins (upstream version, base image digests, published?) | versions.yaml, checked by `make validate` |
| Fixtures | fixtures/, fixtures/schema/opcua-fixture.schema.json |
| What each stack can do | `print-capabilities`, README.md |
| What is done and what is next | PLAN.md |
| What this repository must and must not do | REQUIREMENTS.md |

## Hard rules

1. Nothing floats: upstream versions and base images by digest. `make validate` must pass.
2. Features a stack lacks are declared in `print-capabilities`, never faked.
3. Contract changes update docs/CLIENT_CONTRACT.md and every adapter in the same change.
4. Every adapter reports the release version; `make check-release VERSION=vX.Y.Z` lists what differs.
5. Licences: every redistributed component in THIRD_PARTY_NOTICES.md.

## Commands

| When you change… | Run |
|---|---|
| anything | `make validate` |
| an adapter | `make image-<adapter> test-<adapter> smoke-<adapter>` |
| cross-stack behaviour | `make smoke-cross-stack` |
| PubSub | `make smoke-pubsub` |
| everything | `make ci` |
| a release | `make check-release VERSION=vX.Y.Z` |

## Git and releases

Branches and PRs. Do not push to `main`, push tags or run release workflows unless the maintainer asks in the session.
