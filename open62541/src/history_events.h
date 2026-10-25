#pragma once

#include <cjson/cJSON.h>
#include <open62541.h>

/* client history-read-events / history-update-events (history_events.c). */
int cmd_history_read_events(int argc, char **argv);
int cmd_history_update_events(int argc, char **argv);

/* Helpers, exposed for the self-test. */
int hev_parse_select(const char *path, UA_SimpleAttributeOperand *out);
int hev_parse_timestamps(const char *s, UA_TimestampsToReturn *out);
int hev_parse_perform(const char *s, UA_PerformUpdateType *out, int *isDelete);
int hev_build_where(const UA_NodeId *ofType, int haveMinSev, UA_UInt16 minSev,
                    UA_ContentFilter *out);
int hev_event_value(const cJSON *j, UA_Variant *out, char *err, size_t errLen);

/* Unit tests of the helpers; 0 when all pass. */
int hev_selftest(void);
