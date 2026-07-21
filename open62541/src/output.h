#pragma once

#include <open62541.h>

/*
 * JSON output helpers. All JSON is written to stdout; diagnostics to stderr.
 * No global state other than stdout itself.
 *
 * Every client command emits exactly one JSON object in this order:
 *   {"schemaVersion":"1.0","adapter":"...","operation":"...",
 *    "success":...,"serviceResult":{...},"results":[...],"error":...}
 */

/* -------------------------------------------------------------------------
 * Top-level envelope primitives
 * ---------------------------------------------------------------------- */

/* Emit: {"schemaVersion":"1.0","adapter":"<adapter>","operation":"<op>", */
void output_begin(const char *adapter, const char *op);

/* Emit: ,"success":true|false, */
void output_success(int ok);

/* Emit: ,"serviceResult":{"name":"...","code":N,"severity":"..."} */
void output_service_result(UA_StatusCode code);

/* Emit: }\n and flush.  Callers must emit results+error before calling. */
void output_end(void);

/* -------------------------------------------------------------------------
 * Results / error block (call after output_service_result, before output_end)
 * ---------------------------------------------------------------------- */

/* Emit: ,"results":[ */
void output_open_results(void);

/* Emit: ] */
void output_close_results(void);

/* Emit: ,"error":null */
void output_null_error(void);

/* Emit: ,"results":[],"error":null */
void output_no_results(void);

/* Emit: ,"results":[],"error":{"category":"...","message":"..."} */
void output_error(const char *category, const char *message);

/* -------------------------------------------------------------------------
 * Per-operation result items
 * ---------------------------------------------------------------------- */

/*
 * Emit a single read-result JSON object (no leading comma; caller handles
 * comma-separation when streaming multiple items).
 * Must be called between output_open_results() / output_close_results().
 */
void output_read_result_item(const char *nodeId, UA_StatusCode sc,
                              const char *dataType, int builtInType,
                              const UA_Variant *val, UA_DateTime sourceTs);

/* Convenience: emit ,"results":[{single read result}],"error":null */
void output_read_result(const char *nodeId, UA_StatusCode sc,
                        const char *dataType, int builtInType,
                        const UA_Variant *val, UA_DateTime sourceTs);

/* Emit: ,"results":[{"nodeId":"...","statusCode":{...}}],"error":null */
void output_write_result(const char *nodeId, UA_StatusCode sc);

/*
 * Emit: ,"results":[...all refs...],"error":null
 * refs may be NULL when count == 0.
 */
void output_browse_results(const UA_ReferenceDescription *refs, size_t count);

/* -------------------------------------------------------------------------
 * Utility helpers (also used by client.c)
 * ---------------------------------------------------------------------- */

/* "Good" | "Uncertain" | "Bad" */
const char *output_severity(UA_StatusCode code);

/* Symbolic name, e.g. "Good", "BadNodeIdUnknown".  Never returns NULL. */
const char *output_status_code_name(UA_StatusCode code);

/* Write ISO 8601 UTC string into buf (buf must be at least 32 bytes). */
void output_timestamp(UA_DateTime dt, char *buf, size_t bufLen);

/* OPC UA built-in type integer (1–25), or 0 for unknown. */
int ua_type_to_builtin_id(const UA_DataType *type);

/* Print the JSON value of a UA_Variant to stdout (no key, no leading comma). */
void output_ua_variant_value(const UA_Variant *var);

/* Print: ,"<key>":<value of variant> */
void output_ua_variant_field(const char *key, const UA_Variant *var);

/* Print a UA_NodeId as a JSON string to stdout (includes the surrounding quotes). */
void output_nodeid(const UA_NodeId *nid);

/* Emit the single results item for a call command.
 * Call between output_open_results() and output_close_results(). */
void output_call_result(const char *objectNodeId, const char *methodNodeId,
                        UA_StatusCode sc,
                        const UA_Variant *outputs, size_t outputsSize);

/* Write the JSON representation of a UA_Variant value into buf (NUL-terminated).
 * Returns the number of bytes written (excluding NUL). buf must be >= bufLen. */
int output_variant_to_buf(const UA_Variant *var, char *buf, size_t bufLen);
