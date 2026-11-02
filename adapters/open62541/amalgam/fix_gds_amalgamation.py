#!/usr/bin/env python3
"""Fix: the amalgamation with UA_ENABLE_GDS_PUSHMANAGEMENT compiles
(open62541 v1.5.9).

src/server/ua_server_ns0_gds.c defines two static functions whose names other
translation units use for static functions of their own:
secureChannel_delayedClose (also in src/server/ua_server.c) and writeTrustList
(also in plugins/crypto/ua_certificategroup_filestore.c). Compiled one by one
that is fine; in the single translation unit of the amalgamation
(tools/amalgamate.py) it is a redefinition. Rename them in
ua_server_ns0_gds.c only (whole words).

Only the exact v1.5.9 code is patched; other versions are left as they are
(with a warning).

usage: fix_gds_amalgamation.py <open62541 source root>
"""

import os
import re
import sys

path = os.path.join(sys.argv[1], "src", "server", "ua_server_ns0_gds.c")
with open(path, encoding="utf8") as f:
    text = f.read()

renames = {"secureChannel_delayedClose": "gds_secureChannel_delayedClose",
           "writeTrustList": "gds_writeTrustList"}
for old in renames:
    if not re.search(r"^%s\(" % old, text, re.M):
        print("fix_gds_amalgamation: %s does not define %s as in v1.5.9, not patched"
              % (path, old), file=sys.stderr)
        sys.exit(0)
for old, new in renames.items():
    text = re.sub(r"\b%s\b" % old, new, text)
with open(path, "w", encoding="utf8") as f:
    f.write(text)
print("fix_gds_amalgamation: patched %s" % path)
