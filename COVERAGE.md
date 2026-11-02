# Coverage

What a consumer can exercise against the published adapters today. "Cross-stack"
is what this repository's own self-test covers between the reference stacks
(`make interop`), besides what each image does against itself (`make smoke`) and
in its own tests. The contract has the operations: [docs/CONTAINER_CONTRACT.md](docs/CONTAINER_CONTRACT.md).

| Category | Available to a consumer | Cross-stack self-test |
|----------|-------------------------|-----------------------|
| Discovery | `endpoints`, `find-servers`, `register-server`, `find-servers-on-network` | `endpoints`; LDS between open62541 and Milo; `--register-with` from asyncua to open62541 |
| Attribute services | `read`, `write`, value literals of the contract | yes |
| View services | `browse`, `register-nodes` | yes |
| Method services | `call` on the fixture's methods | yes |
| Subscriptions | Data changes, events, lifecycle, deadbands, SecureChannel renewal under a subscription | data changes, absolute and percent deadband, renewal |
| Node management | AddNodes, DeleteNodes where the stack serves them | no |
| Query | `query` where the stack serves it | no |
| Historical events | `history-read-events`, `history-update-events` (forward, reverse, paging, filters, insert, replace, update, delete) | yes, for the pairs that declare them |
| Alarms and conditions | `alarms` on `s=Alarms.InteropAlarm` | no |
| Security | RSA policies, Sign and SignAndEncrypt, UserName tokens, untrusted certificates | yes, per [tests/secure-cases.tsv](tests/secure-cases.tsv) |
| ECC policies | open62541, both roles | open62541 against itself |
| Certificate chains | `--no-certificate-chain`, chain validation | UA-.NETStandard against open62541 |
| Certificate management (Part 12 push) | `push` | no |
| Global Discovery Server (Part 12 pull) | `dotnet-gds`, `gds-pull` | `dotnet-gds` against itself |
| Reverse connect | open62541, async-opcua, node-opcua | no |
| Other transports | `opc.https`, `opc.wss` on UA-.NETStandard | no |
| Data encodings | `codec`: JSON, XML (open62541, Milo, UA-.NETStandard) | yes, per [tests/codec-cases.tsv](tests/codec-cases.tsv) |
| PubSub (Part 14) | open62541 and UA-.NETStandard: UDP, MQTT, UADP, JSON, message security; open62541 also SKS and the information model | each stack against itself: `make pubsub` |
| Shutdown | SIGTERM exits 0 | each image |

## Not provided on purpose

Malformed messages, wrong sequence numbers and precise timer boundaries. A
reference implementation is a correct peer, not a fault injector; a library tests
these with scripted peers of its own.

## Per adapter

| | open62541 | milo | async-opcua | dotnet | node-opcua | asyncua | dotnet-gds |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| The core services above | yes | yes | yes | yes | yes | yes | endpoints, GDS only |
| Deadband, served | yes | yes | yes | yes | yes | no | no |
| Reverse connect | yes | no | yes | no | yes | no | no |
| ECC policies | yes | no | no | no | no | no | no |
| LDS and mDNS, served | yes | no | no | no | no | no | no |
| Node management, served | yes | no | yes | yes | no | no | no |
| `codec` | yes | yes | no | yes | no | no | no |
| PubSub | yes | no | no | yes | no | no | no |
| GDS server | no | no | no | no | no | no | yes |

The reasons are in [docs/CAPABILITIES.md](docs/CAPABILITIES.md) and
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Read them from the image
(`print-capabilities`) rather than from this table.
