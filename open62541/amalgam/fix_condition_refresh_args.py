#!/usr/bin/env python3
"""Fix: ConditionRefresh / ConditionRefresh2 accept their SubscriptionId /
MonitoredItemId arguments (open62541 v1.5.9, Alarms & Conditions).

The Call service adjusts every input argument to the DataType of the
method's InputArguments before the callback runs (adjustValueType in
src/server/ua_services_attribute.c). The arguments of ConditionRefresh(2) are
IntegerId (i=288). With UA_ENABLE_PUBSUB the generated type table contains
IntegerId (tools/schema/datatypes_pubsub.txt), so a UInt32 argument arrives
in the callback as an IntegerId variant, and checkConditionRefreshArguments
(src/server/ua_subscription_alarms_conditions.c) rejects it with
Bad_InvalidArgument because it only accepts UA_TYPES_UINT32: ConditionRefresh
can then not be called at all. IntegerId is an alias of UInt32 with the same
memory layout, so the check accepts both.

Only the exact v1.5.9 code is patched; other versions are left as they are
(with a warning).

usage: fix_condition_refresh_args.py <open62541 source root>
"""

import os
import sys

path = os.path.join(sys.argv[1], "src", "server", "ua_subscription_alarms_conditions.c")
with open(path, encoding="utf8") as f:
    text = f.read()

old = """        if(!UA_Variant_hasScalarType(&input[i], &UA_TYPES[UA_TYPES_UINT32]))
            return UA_STATUSCODE_BADINVALIDARGUMENT;"""
new = """        /* opcua-interop fix: IntegerId (alias of UInt32, generated with PubSub) */
        if(!UA_Variant_isScalar(&input[i]) || !input[i].type ||
           input[i].type->typeKind != UA_DATATYPEKIND_UINT32)
            return UA_STATUSCODE_BADINVALIDARGUMENT;"""

if text.count(old) != 1:
    print("fix_condition_refresh_args: %s does not match v1.5.9, not patched" % path,
          file=sys.stderr)
    sys.exit(0)
text = text.replace(old, new)
with open(path, "w", encoding="utf8") as f:
    f.write(text)
print("fix_condition_refresh_args: patched %s" % path)
