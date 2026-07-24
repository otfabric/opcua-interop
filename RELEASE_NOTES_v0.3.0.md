# opcua-interop v0.3.0

Phase 13 adapter support for go-opcua exact queues / subscription timestamps / matrix IndexRange.

## Changes

- **subscribe `--timestamps`** (`Source` | `Server` | `Both` | `Neither`, default `Both`) on open62541 and Milo clients — passed through CreateMonitoredItems
- **subscribe JSON `serverTimestamp`** emitted when the DataValue carries a server timestamp (alongside existing `sourceTimestamp`)
- Existing `--queue-size` / `--discard-oldest` / `--index-range` unchanged (matrix IndexRange is a string on the existing flag)

## Images

- `ghcr.io/otfabric/opcua-interop-open62541:v0.3.0`
- `ghcr.io/otfabric/opcua-interop-milo:v0.3.0`
