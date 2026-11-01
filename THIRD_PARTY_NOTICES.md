# Third-party notices

The repository's own adapters, fixtures, scripts and documentation are MIT ([LICENSE](LICENSE)). Each published image also contains its upstream stack under that stack's licence. Consumers talk to the images over the network and are not linked to them.

| Image | Upstream | Pin | Upstream licence | Source |
|---|---|---|---|---|
| `opcua-interop-open62541` | open62541 | v1.5.9 | MPL-2.0 | https://github.com/open62541/open62541 |
| `opcua-interop-milo` | Eclipse Milo | 1.1.8 | EPL-2.0 | https://github.com/eclipse-milo/milo |
| `opcua-interop-async-opcua` | async-opcua | 0.19.0 | MPL-2.0 | https://github.com/FreeOpcUa/async-opcua |
| `opcua-interop-dotnet` | OPC Foundation UA-.NETStandard | 2.0.1 | OPC Foundation MIT License 1.00 (`requireLicenseAcceptance` on NuGet) | https://github.com/OPCFoundation/UA-.NETStandard |
| `opcua-interop-dotnet-gds` | OPC Foundation UA-.NETStandard GDS | 2.0.1 | OPC Foundation MIT License 1.00 (`requireLicenseAcceptance` on NuGet) | https://github.com/OPCFoundation/UA-.NETStandard |
| `opcua-interop-node-opcua` | node-opcua | 2.187.12 | MIT | https://github.com/node-opcua/node-opcua |
| `opcua-interop-asyncua` | opcua-asyncio (PyPI `asyncua`) | 2.1.0 | LGPL-3.0 | https://github.com/FreeOpcUa/opcua-asyncio |
| `opcua-interop-otfabric` | go-opcua (OT Fabric's own stack, not in a harness release) | latest release when built | MIT | https://github.com/otfabric/go-opcua |

The PubSub smoke test runs `eclipse-mosquitto:2.0.22` (EPL-2.0 OR BSD-3-Clause), pulled from Docker Hub by digest and not redistributed here. Transitive dependencies are locked per adapter and keep their own licences; those of `opcua-interop-otfabric` and the Go standard library (1.27.2, BSD-3-Clause) are in the image under `/licenses`.

Redistributing an image means keeping the upstream notices and meeting the source obligations of its licence. The images do not yet carry licence texts under `/licenses/`.
