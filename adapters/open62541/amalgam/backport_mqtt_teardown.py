#!/usr/bin/env python3
"""Backport: no double free when an MQTT broker connection drops while one
of its topic connections is already shutting down (open62541 v1.5.9).

MQTT_shutdownConnection (arch/common/eventloop_mqtt.c) marks a topic
connection CLOSING and schedules removeTopicConnectionDelayed for the next
EventLoop iteration. If the broker TCP connection closes first (for example a
refused connect while the WriterGroup goes to Error after a failed send),
removeBrokerConnection frees every topic connection, including that one, and
the delayed callback then frees it a second time: the process aborts with
"double free or corruption". Upstream master fixed this (2026, "MQTT delayed
removal"); this script applies the topic-connection part of that fix:

  * removeTopicConnection detaches the topic connection from its broker but
    leaves the memory to a pending delayed callback;
  * removeTopicConnectionDelayed frees a detached topic connection, and runs
    the normal removal otherwise.

Only the exact v1.5.9 code is patched; other versions are left as they are
(with a warning).

usage: backport_mqtt_teardown.py <open62541 source root>
"""

import os
import sys

path = os.path.join(sys.argv[1], "arch", "common", "eventloop_mqtt.c")
with open(path, encoding="utf8") as f:
    text = f.read()

replacements = [
    (
        """    /* Free the memory */
    UA_String_clear(&tc->topic);
    UA_free(tc);

    /* The last topic connection was removed. Close the broker connection. */""",
        """    /* opcua-interop backport (upstream master): a pending delayed removal
     * frees the memory; detach from the broker that may be freed first. */
    tc->brokerConnection = NULL;
    if(!tc->dc.callback) {
        UA_String_clear(&tc->topic);
        UA_free(tc);
    }

    /* The last topic connection was removed. Close the broker connection. */""",
    ),
    (
        """    MQTTTopicConnection *tc = (MQTTTopicConnection*)context;
    removeTopicConnection(tc);
}""",
        """    MQTTTopicConnection *tc = (MQTTTopicConnection*)context;
    tc->dc.callback = NULL;
    if(tc->brokerConnection) {
        removeTopicConnection(tc);
    } else {
        UA_String_clear(&tc->topic);
        UA_free(tc);
    }
}""",
    ),
]

for old, new in replacements:
    if text.count(old) != 1:
        print("backport_mqtt_teardown: %s does not match v1.5.9, not patched"
              % path, file=sys.stderr)
        sys.exit(0)

for old, new in replacements:
    text = text.replace(old, new)

with open(path, "w", encoding="utf8") as f:
    f.write(text)
print("backport_mqtt_teardown: patched %s" % path)
