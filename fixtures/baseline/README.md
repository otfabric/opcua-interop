# Baseline Fixture

The baseline fixture defines the primary interoperability address space. Both adapters (open62541 and Milo) must construct an equivalent namespace from this single file.

## Address space layout

```
Objects (i=85)
└── Compatibility  (nsu=urn:otfabric:opcua-compat:model;s=Compatibility)
    ├── Scalars       — one readable/writable variable per built-in scalar type
    ├── Arrays        — empty, one-element, multi-element, string, ByteString, 2D matrix
    ├── Dynamic       — deterministic value generators (counter, toggle, ramp)
    ├── Access        — read-write, read-only, write-only
    ├── Methods       — Add, Multiply, Echo, NoArguments, MultipleOutputs, Fail
    ├── DataValues    — variables with specific status codes and timestamp behavior
    └── Diagnostics   — adapter name, stack version, fixture id
```

## Namespace

| Alias | URI |
|---|---|
| `compat` | `urn:otfabric:opcua-compat:model` |

Runtime namespace indices differ between stacks. Always reference nodes by namespace URI in tests.

## Scalar initial values

These values are chosen to reveal binary encoding errors:

| Node | Type | Value |
|---|---|---|
| `Scalar.Boolean` | Boolean | `true` |
| `Scalar.SByte` | SByte | `-100` |
| `Scalar.Byte` | Byte | `200` |
| `Scalar.Int16` | Int16 | `-12345` |
| `Scalar.UInt16` | UInt16 | `54321` |
| `Scalar.Int32` | Int32 | `-123456789` |
| `Scalar.UInt32` | UInt32 | `3234567890` |
| `Scalar.Int64` | Int64 | `-1234567890123456789` |
| `Scalar.UInt64` | UInt64 | `12345678901234567890` |
| `Scalar.Float` | Float | `12.5` |
| `Scalar.Double` | Double | `-12345.6789` |
| `Scalar.String` | String | `"OPC UA – 兼容性 – Δ"` |
| `Scalar.DateTime` | DateTime | `2024-01-01T00:00:00Z` |
| `Scalar.Guid` | Guid | `72962b91-fa75-4ae6-8d28-b404dc7daf63` |
| `Scalar.ByteString` | ByteString | `opcua-compat` (base64) |
| `Scalar.XmlElement` | XmlElement | `<compat>test</compat>` |
| `Scalar.NodeId` | NodeId | `i=85` |
| `Scalar.QualifiedName` | QualifiedName | `0:Objects` |
| `Scalar.LocalizedText` | LocalizedText | `en:OPC UA Compatibility` |
| `Scalar.StatusCode` | StatusCode | `0x00000000` (Good) |

## Dynamic behaviors

| Node | Kind | Interval | Description |
|---|---|---|---|
| `Dynamic.Counter` | counter | 250 ms | Int64, starts at 0, increments by 1 |
| `Dynamic.Toggle` | toggle | 500 ms | Boolean, alternates true/false |
| `Dynamic.Ramp` | ramp | 100 ms | Double, 0.0→100.0 then resets |

## Methods

| Method | Behavior |
|---|---|
| `Methods.Add` | Returns `Int32(a + b)` |
| `Methods.Multiply` | Returns `Double(a * b)` |
| `Methods.Echo` | Returns input String unchanged |
| `Methods.NoArguments` | Returns `Boolean(true)` |
| `Methods.MultipleOutputs` | Returns `Int32(input * 2)` and `String(input)` |
| `Methods.Fail` | Returns `BadInternalError` service result |

## Access levels

| Node | Access |
|---|---|
| `Access.ReadWrite` | CurrentRead + CurrentWrite |
| `Access.ReadOnly` | CurrentRead only |
| `Access.WriteOnly` | CurrentWrite only (reads return BadNotReadable) |

## Users

| Username | Password | Roles |
|---|---|---|
| `test-user` | `test-password` | AuthenticatedUser |

These credentials are for isolated test environments only.

## Schema version

`1.0`
