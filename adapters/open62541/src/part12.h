#pragma once

/*
 * Helpers shared by `client push` (Part 12 §7, CONTAINER_CONTRACT §15) and
 * `client gds-pull` (Part 12 §6 / §7.9, §16.2). open62541 v1.5.9 has neither
 * a push nor a GDS client API, so both commands are plain method calls
 * (UA_Client_call) built on these helpers: a JSON builder for the result
 * item, argument / file parsing, Variant constructors, browse path
 * translation and the TrustList file read.
 */

#include <open62541.h>

#include <stddef.h>

/* BadNamespaceUriInvalid (Part 4) is not in the v1.5.9 status code table. */
#ifndef UA_STATUSCODE_BADNAMESPACEURIINVALID
#define UA_STATUSCODE_BADNAMESPACEURIINVALID ((UA_StatusCode)0x80530000U)
#endif

/* -------------------------------------------------------------------------
 * JSON builder: the result item is built in memory because the envelope's
 * success / serviceResult precede it on stdout.
 * ---------------------------------------------------------------------- */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    int    first; /* no member written yet in the innermost object / array */
    int    oom;
} P12Json;

void p12j_init(P12Json *j);
void p12j_free(P12Json *j);
void p12j_raw(P12Json *j, const char *s);
void p12j_printf(P12Json *j, const char *fmt, ...);
/* ,"key": (comma unless first). */
void p12j_key(P12Json *j, const char *key);
/* A separator inside an array (comma unless first). */
void p12j_sep(P12Json *j);
void p12j_open(P12Json *j, char c);  /* '{' or '[' */
void p12j_close(P12Json *j, char c); /* '}' or ']' */
void p12j_str(P12Json *j, const char *data, size_t len);
void p12j_cstr(P12Json *j, const char *s);
void p12j_uastr(P12Json *j, const UA_String *s); /* null for the null string */
void p12j_b64(P12Json *j, const UA_Byte *data, size_t len);
void p12j_nodeid(P12Json *j, const UA_NodeId *id);
void p12j_status(P12Json *j, UA_StatusCode sc);
void p12j_datetime(P12Json *j, UA_DateTime dt); /* null for the null DateTime */
/* "key":{status} */
void p12j_status_field(P12Json *j, const char *key, UA_StatusCode sc);
/* "key":"<base64>" */
void p12j_b64_field(P12Json *j, const char *key, const UA_ByteString *bs);
/* "key":[base64 ...] of a ByteString array Variant (empty when not one) */
void p12j_b64_array_field(P12Json *j, const char *key, const UA_Variant *v);
/* "key":[nodeId ...] of a NodeId array Variant (empty when not one) */
void p12j_nodeid_array_field(P12Json *j, const char *key, const UA_Variant *v);
/* The TrustListDataType object (§4 `push`, §16.2). */
void p12j_trust_list(P12Json *j, const UA_TrustListDataType *tl);

/* -------------------------------------------------------------------------
 * Arguments
 * ---------------------------------------------------------------------- */

/* Presence of a flag that takes no value. */
int p12_has_flag(int argc, char **argv, const char *flag);
/* All values of a repeatable flag (pointers into argv; free the array). */
const char **p12_all_values(int argc, char **argv, const char *flag, size_t *n);
/* Parse an unsigned decimal in [0, max]; 0 on success. */
int p12_parse_uint(const char *s, unsigned long max, unsigned long *out);
/* Read a whole file. 0 on success (out owns the bytes). */
int p12_read_file(const char *path, UA_ByteString *out);
/* Read a certificate (PEM or DER file) as DER. 0 on success. */
int p12_read_certificate(const char *path, UA_ByteString *out);
/* A NodeId flag value: §8 syntax including nsu= (resolved on the
 * connected client). 0 on success. */
int p12_resolve_nodeid(UA_Client *client, const char *s, UA_NodeId *out);

/* -------------------------------------------------------------------------
 * Variants (each sets a copy; UA_Variant_clear frees it)
 * ---------------------------------------------------------------------- */

void p12v_nodeid(UA_Variant *v, const UA_NodeId *id);
void p12v_string(UA_Variant *v, const char *s); /* NULL: the null String */
void p12v_bool(UA_Variant *v, UA_Boolean b);
void p12v_byte(UA_Variant *v, UA_Byte b);
void p12v_uint16(UA_Variant *v, UA_UInt16 x);
void p12v_uint32(UA_Variant *v, UA_UInt32 x);
void p12v_int32(UA_Variant *v, UA_Int32 x);
void p12v_bytestring(UA_Variant *v, const UA_ByteString *bs);
void p12v_string_array(UA_Variant *v, const char **s, size_t n);
void p12v_bytestring_array(UA_Variant *v, const UA_ByteString *bs, size_t n);
void p12v_clear_all(UA_Variant *v, size_t n);

/* Scalar accessors of an output argument (NULL / default when absent). */
const UA_NodeId *p12_out_nodeid(const UA_Variant *out, size_t n, size_t i);
const UA_ByteString *p12_out_bytestring(const UA_Variant *out, size_t n, size_t i);
int p12_out_bool(const UA_Variant *out, size_t n, size_t i);

/* -------------------------------------------------------------------------
 * Services
 * ---------------------------------------------------------------------- */

/* A status that means the connection is gone (exit 3) or timed out (exit 7):
 * the command fails as a whole instead of recording a step status. */
int p12_is_transport(UA_StatusCode sc);

/* One method call. Returns the call's status (the service result when the
 * Call service failed); outputs are owned by the caller (p12_free_outputs). */
UA_StatusCode p12_call(UA_Client *client, const UA_NodeId *object,
                       const UA_NodeId *method, UA_Variant *inputs, size_t nIn,
                       UA_Variant **outputs, size_t *nOut);
void p12_free_outputs(UA_Variant *outputs, size_t n);

/* Resolve n ns=0 browse paths (each a NULL-terminated list of BrowseNames)
 * from start over HierarchicalReferences: the first target of each, or the
 * status of the first path that does not resolve. */
UA_StatusCode p12_translate(UA_Client *client, const UA_NodeId *start,
                            const char *const *const *paths, size_t n,
                            UA_NodeId *out);

/* Read a TrustList file object: OpenWithMasks(masks) when withMasks, else
 * Open(Read); Read in 4096-byte chunks; Close; decode TrustListDataType.
 * *tl is initialised by the call and must be cleared by the caller on
 * success. */
UA_StatusCode p12_read_trust_list(UA_Client *client, const UA_NodeId *trustList,
                                  int withMasks, UA_UInt32 masks,
                                  UA_TrustListDataType *tl);

/* The binary body of an ExtensionObject: the encoded body, or the decoded
 * value encoded again. 0 on success (out owns the bytes). */
int p12_extension_body(const UA_ExtensionObject *eo, UA_ByteString *out);

/* The bytes one binary-encoded NodeId takes at the start of buf, 0 if
 * malformed. */
size_t p12_nodeid_encoded_length(const UA_Byte *buf, size_t len);

/* Emit the envelope with one result item (or none when item is NULL). */
void p12_emit(const char *op, int ok, UA_StatusCode sc, const char *category,
              const char *message, const P12Json *item);

/* Exit code of a failed command status: 7 timeout, 3 transport, else 4. */
int p12_exit_code(UA_StatusCode sc);
