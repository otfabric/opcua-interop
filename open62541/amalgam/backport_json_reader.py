#!/usr/bin/env python3
"""Backport: let open62541 v1.5.9 DataSetReaders accept JSON NetworkMessages.

In v1.5.9, UA_DataSetReader_checkIdentifier (src/pubsub/ua_pubsub_reader.c)
has an unimplemented TODO for ReaderGroups with JSON encoding and returns
BadNotFound for *every* JSON NetworkMessage, so a JSON subscriber (e.g.
pubsub-mqtt-json) decodes messages and then drops them ("Message received that
could not be processed"). Upstream master fixed this (2026-09, "fix(pubsub)"
series on ua_pubsub_reader.c); this script applies the same matching logic to
the v1.5.9 sources before the amalgamation is generated:

  * the PublisherId is compared by value across the numeric widths for JSON
    (the JSON mapping carries every numeric PublisherId as a string, so the
    decoder cannot know whether the publisher used Byte, UInt16, UInt32 or
    UInt64); strings are compared as strings;
  * the DataSetWriterIds decoded from the JSON DataSetMessages are matched
    against the reader's DataSetWriterId (0 accepts any writer).

Nothing else changes: UADP matching is untouched. Only the exact v1.5.9 code
is patched; other versions are left as they are (with a warning).

usage: backport_json_reader.py <open62541 source root>
"""

import os
import sys

path = os.path.join(sys.argv[1], "src", "pubsub", "ua_pubsub_reader.c")
with open(path, encoding="utf8") as f:
    text = f.read()

old_check = """UA_StatusCode
UA_DataSetReader_checkIdentifier(UA_PubSubManager *psm, UA_DataSetReader *dsr,
                                 UA_NetworkMessage *msg) {
    if(!publisherIdIsMatching(msg, &dsr->config.publisherId)) {"""

new_check = """/* opcua-interop backport (upstream master): JSON carries numeric
 * PublisherIds as strings, compare them by value across integer widths. */
static UA_Boolean
publisherIdIsMatchingJson(UA_NetworkMessage *msg, UA_PublisherId *idB) {
    if(!msg->publisherIdEnabled)
        return true;
    UA_PublisherId *idA = &msg->publisherId;
    if(idA->idType == UA_PUBLISHERIDTYPE_STRING ||
       idB->idType == UA_PUBLISHERIDTYPE_STRING)
        return publisherIdIsMatching(msg, idB);
    UA_UInt64 a = 0, b = 0;
    switch(idA->idType) {
    case UA_PUBLISHERIDTYPE_BYTE:   a = idA->id.byte; break;
    case UA_PUBLISHERIDTYPE_UINT16: a = idA->id.uint16; break;
    case UA_PUBLISHERIDTYPE_UINT32: a = idA->id.uint32; break;
    case UA_PUBLISHERIDTYPE_UINT64: a = idA->id.uint64; break;
    default: return false;
    }
    switch(idB->idType) {
    case UA_PUBLISHERIDTYPE_BYTE:   b = idB->id.byte; break;
    case UA_PUBLISHERIDTYPE_UINT16: b = idB->id.uint16; break;
    case UA_PUBLISHERIDTYPE_UINT32: b = idB->id.uint32; break;
    case UA_PUBLISHERIDTYPE_UINT64: b = idB->id.uint64; break;
    default: return false;
    }
    return a == b;
}

UA_StatusCode
UA_DataSetReader_checkIdentifier(UA_PubSubManager *psm, UA_DataSetReader *dsr,
                                 UA_NetworkMessage *msg) {
    UA_Boolean isJson = (dsr->linkedReaderGroup &&
        dsr->linkedReaderGroup->config.encodingMimeType == UA_PUBSUB_ENCODING_JSON);
    if(!(isJson ? publisherIdIsMatchingJson(msg, &dsr->config.publisherId)
                : publisherIdIsMatching(msg, &dsr->config.publisherId))) {"""

old_json = """    if(rg->config.encodingMimeType == UA_PUBSUB_ENCODING_JSON) {
        // TODO
        /* if(dsr->config.dataSetWriterId == */
        /*    *msg->payloadHeader.dataSetPayloadHeader.dataSetWriterIds) { */
        /*     return UA_STATUSCODE_GOOD; */
        /* } */

        /* UA_LOG_DEBUG_PUBSUB(psm->logging, dsr, "DataSetWriterId does not match. " */
        /*                     "Expected %u, received %u", dsr->config.dataSetWriterId, */
        /*                     *msg->payloadHeader.dataSetPayloadHeader.dataSetWriterIds); */
        return UA_STATUSCODE_BADNOTFOUND;
    }"""

new_json = """    if(rg->config.encodingMimeType == UA_PUBSUB_ENCODING_JSON) {
        /* opcua-interop backport (upstream master): match the writer ids
         * decoded from the JSON DataSetMessages. 0 accepts any writer. */
        if(dsr->config.dataSetWriterId == 0)
            return UA_STATUSCODE_GOOD;
        for(size_t i = 0; i < msg->messageCount; i++) {
            if(dsr->config.dataSetWriterId == msg->dataSetWriterIds[i])
                return UA_STATUSCODE_GOOD;
        }
        UA_LOG_DEBUG_PUBSUB(psm->logging, dsr, "DataSetWriterId does not match. "
                            "Expected %u", dsr->config.dataSetWriterId);
        return UA_STATUSCODE_BADNOTFOUND;
    }"""

# Applied only to the exact v1.5.9 code. A newer upstream (the Upstream
# workflow builds the latest release) that already contains the fix,
# or changed this code, is left alone; scripts/pubsub-smoke.sh (mqtt-json)
# shows whether JSON subscribing works there.
applied = 0
for old, new in ((old_check, new_check), (old_json, new_json)):
    if text.count(old) == 1:
        text = text.replace(old, new, 1)
        applied += 1
if applied != 2:
    print("backport_json_reader.py: WARNING: v1.5.9 code not found in %s (%d/2 hunks "
          "applied) - not patched" % (path, applied))
    sys.exit(0)

with open(path, "w", encoding="utf8") as f:
    f.write(text)
print("backport_json_reader.py: JSON DataSetReader matching patched in %s" % path)
