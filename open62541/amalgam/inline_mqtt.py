#!/usr/bin/env python3
"""Inline the MQTT-C sources into open62541's MQTT EventLoop plugin.

open62541 v1.5.9 builds MQTT support (UA_ENABLE_MQTT) by textually including
the MQTT-C submodule from arch/common/eventloop_mqtt.c:

    #include "../../deps/mqtt-c/include/mqtt.h"
    #include "../../deps/mqtt-c/src/mqtt.c"

tools/amalgamate.py drops every quoted #include line when it concatenates the
sources into open62541.c, so with UA_ENABLE_AMALGAMATION=ON the amalgamation
lacks MQTT-C entirely and does not compile ("field 'client' has incomplete
type", "MQTT_OK undeclared"). This script replaces the two include lines by the
content of the two files *before* the amalgamation is generated, so the
amalgamated open62541.c is self-contained again. The include lines inside the
MQTT-C files that would survive amalgamation (<mqtt.h>, <mqtt_pal.h>) are
removed: eventloop_mqtt.c defines the PAL itself (it sets __MQTT_PAL_H__).

usage: inline_mqtt.py <open62541 source root>
"""

import os
import sys

root = sys.argv[1]
plugin = os.path.join(root, "arch", "common", "eventloop_mqtt.c")
header = os.path.join(root, "deps", "mqtt-c", "include", "mqtt.h")
source = os.path.join(root, "deps", "mqtt-c", "src", "mqtt.c")

for path in (plugin, header, source):
    if not os.path.isfile(path):
        sys.exit("inline_mqtt.py: missing %s (is the mqtt-c submodule checked out?)" % path)


def body(path, drop):
    out = []
    with open(path, encoding="utf8") as f:
        for line in f:
            if line.strip() in drop:
                out.append("/* inline_mqtt.py: removed %s */\n" % line.strip())
            else:
                out.append(line)
    return "".join(out)


mqtt_h = body(header, {"#include <mqtt_pal.h>"})
mqtt_c = body(source, {"#include <mqtt.h>"})

with open(plugin, encoding="utf8") as f:
    text = f.read()

inc_h = '#include "../../deps/mqtt-c/include/mqtt.h"'
inc_c = '#include "../../deps/mqtt-c/src/mqtt.c"'
if inc_h not in text or inc_c not in text:
    # A newer upstream may include MQTT-C differently; leave it alone.
    print("inline_mqtt.py: WARNING: include lines not found in %s - not patched" % plugin)
    sys.exit(0)

text = text.replace(inc_h, "/* ---- inlined deps/mqtt-c/include/mqtt.h ---- */\n" + mqtt_h, 1)
text = text.replace(inc_c, "/* ---- inlined deps/mqtt-c/src/mqtt.c ---- */\n" + mqtt_c, 1)

with open(plugin, "w", encoding="utf8") as f:
    f.write(text)
print("inline_mqtt.py: MQTT-C inlined into %s" % plugin)
