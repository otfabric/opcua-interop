#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Turn what scripts/results.sh logged into the organisation's interop-result-v1.

    scripts/results-from-log.py <report dir> <results.json>

The report directory holds results.log (one tab-separated line per result: id,
outcome, roles as "role=name" words, milliseconds, reason, waiver),
implementations.tsv (name, image), started and commands. A known-difference
names its waiver in tests/known-differences.tsv; a fail that names a waiver
says the deviation is gone. The exit status is 1 when the run failed: a fail or
infra-error, a waiver that no longer reproduces, or no pass at all
(scripts/interop_result.py).
"""

import re
import sys
from pathlib import Path

import interop_result

ROOT = Path(__file__).resolve().parent.parent
OUTCOMES = set(interop_result.OUTCOMES)


def lines(path):
    return path.read_text().splitlines() if path.exists() else []


def load_waivers(path=ROOT / "tests" / "known-differences.tsv"):
    waivers = {}
    for line in lines(path):
        if line.strip() and not line.startswith("#"):
            wid, scope, _, evidence, _ = line.split("\t")
            waivers[wid] = {"id": wid, "scope": scope, "evidence": evidence}
    return waivers


def pins(path=ROOT / "versions.yaml"):
    """implementation -> version, revision and licence, from versions.yaml."""
    out, name, inside = {}, None, False
    for line in lines(path):
        if re.match(r"^\S", line):
            inside = line.startswith("implementations:")
        m = re.match(r"^  ([A-Za-z0-9._-]+):\s*$", line)
        if inside and m:
            name = m.group(1)
            out[name] = {}
        m = re.match(r'^    (version|revision|tag_commit|license): "?([^"#]+?)"?\s*(#.*)?$', line)
        if inside and name and m:
            out[name]["revision" if m.group(1) == "tag_commit" else m.group(1)] = m.group(2)
    return out


def parse_result(line, waivers):
    rid, outcome, roles, ms, reason, waiver = line.split("\t")
    if outcome not in OUTCOMES:
        raise SystemExit("%s: unknown outcome %r" % (rid, outcome))
    parts = rid.split(".")
    res = {"id": rid, "suite": parts[0], "feature": parts[1] if len(parts) > 1 else parts[0],
           "roles": dict(r.split("=", 1) for r in roles.split()), "outcome": outcome, "durationMs": int(ms)}
    if outcome != "pass":
        res["reason"] = reason or outcome
    if waiver and waiver not in waivers:
        raise SystemExit("%s: waiver %s has no line in tests/known-differences.tsv" % (rid, waiver))
    if outcome == "known-difference":
        if not waiver:
            raise SystemExit("%s: known-difference without a waiver" % rid)
        res["waiver"] = waiver
    return res, waiver


def implementations(rows, versions, digest=interop_result.repo_digest):
    out = []
    for name, (image, *own) in {r.split("\t")[0]: r.split("\t")[1:] for r in rows}.items():
        pin = versions.get(name, {})
        i = {"name": name, "version": pin.get("version", "unrecorded"), "independent": True}
        i.update({k: pin[k] for k in ("revision", "license") if k in pin})
        if own:  # An image of our own stack, which reported its version and commit.
            i.update({"version": own[0], "revision": own[1], "independent": False})
        pinned = digest(image)
        if pinned:
            i["image"] = pinned
        out.append(i)
    return out or [{"name": "none", "version": "none"}]


def convert(work, finished, waivers):
    results, reproduced = [], {}
    for line in lines(work / "results.log"):
        res, waiver = parse_result(line, waivers)
        results.append(res)
        if waiver:
            reproduced[waiver] = reproduced.get(waiver, True) and res["outcome"] == "known-difference"
    started = lines(work / "started")
    return {"schemaVersion": "1.0", "repository": "otfabric/opcua-interop",
            "interopVersion": interop_result.version_field(str(ROOT), "interop_version"),
            "contractVersion": interop_result.version_field(str(ROOT), "contract_version"),
            "gitSha": interop_result.git_sha(str(ROOT)), "startedAt": started[0] if started else finished, "finishedAt": finished,
            "host": interop_result.host(),
            "implementations": implementations(lines(work / "implementations.tsv"), pins()),
            "waivers": [{"id": w, "scope": waivers[w]["scope"], "evidence": waivers[w]["evidence"], "reproduced": seen}
                        for w, seen in sorted(reproduced.items())],
            "reproduce": " && ".join(dict.fromkeys(lines(work / "commands"))), "results": results}


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    doc = convert(Path(argv[0]), interop_result.now(), load_waivers())
    interop_result.write(argv[1], doc)
    bad = interop_result.schema_errors(doc) + interop_result.problems(doc)
    print("%s: %s" % (argv[1], ", ".join("%d %s" % (doc["summary"][o], o) for o in interop_result.OUTCOMES)))
    for p in bad:
        print("FAIL " + p, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
