#pragma once

#include <stddef.h>

#include <open62541.h>

/*
 * Literal value parsing shared by `write --type/--value`, `call --input` and
 * `codec encode --type/--value`. Covers all 25 OPC UA built-in types, 1-D
 * arrays (`Type[]`) and matrices (`Type[]` plus dimensions).
 *
 * Literal forms (docs/CONTAINER_CONTRACT.md §12):
 *   Boolean          true | false | 1 | 0
 *   SByte..UInt64    decimal integer
 *   Float, Double    decimal; NaN, Infinity, -Infinity
 *   String           the text itself
 *   DateTime         RFC 3339 UTC, up to 7 fractional digits
 *   Guid             xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 *   ByteString       Base64
 *   XmlElement       the XML text itself
 *   NodeId           i=85 | ns=1;s=x | ns=1;g=<guid> | ns=1;b=<base64>
 *   ExpandedNodeId   [svr=<n>;][nsu=<uri>;|ns=<n>;]<i|s|g|b>=<id>
 *   StatusCode       decimal or 0x-prefixed uint32
 *   QualifiedName    <ns>:<name>
 *   LocalizedText    <locale>:<text>
 *   ExtensionObject  <typeId NodeId>|<Base64 binary body>
 *   DataValue        <Type>:<literal>           (value only)
 *   Variant          <Type>:<literal>
 *   DiagnosticInfo   key=value;...  keys: symbolicId, namespaceUri,
 *                    localizedText, locale, additionalInfo, innerStatusCode
 *
 * Array literals are either comma-separated (`1,2,3`) or a JSON array
 * (`["a,b","c"]`) when elements contain commas. An empty literal is an empty
 * array.
 */

/* Built-in type for a name ("Int32", "NodeId", ...); NULL when unknown. */
const UA_DataType *value_builtin_type(const char *name);

/* Built-in type name for a UA_DataType, or the type's own name. */
const char *value_type_name(const UA_DataType *type);

/*
 * Parse `typeStr` (`Type` or `Type[]`) and `valStr` into *out (initialised
 * here). `dims` is an optional comma-separated ArrayDimensions list for
 * matrices (NULL for none). Returns 0 on success; on failure returns -1 and
 * fills errBuf.
 */
int value_parse(const char *typeStr, const char *valStr, const char *dims,
                UA_Variant *out, char *errBuf, size_t errLen);

/* RFC 3339 UTC -> UA_DateTime (100 ns ticks). Returns 0 on success. */
int value_parse_datetime(const char *s, UA_DateTime *out);

/* Base64 helpers; results are malloc'd (caller frees). */
char *value_b64_encode(const unsigned char *data, size_t len);
unsigned char *value_b64_decode(const char *in, size_t *outLen);
