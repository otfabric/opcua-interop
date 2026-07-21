#pragma once

#include <open62541.h>

/*
 * JSON output helpers. All JSON is written to stdout; diagnostics to stderr.
 * No state is shared between calls except the open FILE* for stdout.
 */

/* Begin a top-level JSON result object: { "operation": "<op>", */
void output_begin(const char *op);

/* Append "success": true|false, */
void output_success(int ok);

/* Append "serviceResult": "<name>", */
void output_service_result(UA_StatusCode code);

/* Close the top-level object and flush stdout. */
void output_end(void);

/* Append a JSON key whose value is a UA_Variant (scalar or array). */
void output_ua_variant_field(const char *key, const UA_Variant *var);

/* Print just the JSON value of a UA_Variant (no key, no leading comma). */
void output_ua_variant_value(const UA_Variant *var);

/* Return a static human-readable name for a status code, e.g. "Good". */
const char *output_status_code_name(UA_StatusCode code);

/* Write an ISO 8601 UTC timestamp string into buf (at least 32 bytes). */
void output_timestamp(UA_DateTime dt, char *buf, size_t bufLen);

/* Emit a complete "results" array containing a single read result. */
void output_read_result(const char *nodeId, UA_StatusCode sc,
                        const char *dataType, const UA_Variant *val,
                        UA_DateTime sourceTs);

/* Emit a complete "references" array from a browse response. */
void output_browse_results(const UA_BrowseResult *result);
