#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of scripts/results-from-log.py that need no Docker."""

import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import interop_result

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("results_from_log", os.path.join(HERE, "results-from-log.py"))
rl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rl)

ROLES = "client=a server=b"
WAIVERS = {"w": {"id": "w", "scope": "server@b", "evidence": "https://example.com/bug"}}


def line(rid, outcome, reason="", waiver=""):
    return "\t".join((rid, outcome, ROLES, "3", reason, waiver))


def convert(*log):
    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        (work / "results.log").write_text("".join(x + "\n" for x in log))
        (work / "implementations.tsv").write_text("a\timage-a\nb\timage-b\na\timage-a\n")
        (work / "started").write_text("2026-10-30T00:00:00Z\n")
        (work / "commands").write_text("REPORT_DIR=reports smoke.sh cross\nREPORT_DIR=reports smoke.sh cross\n")
        with mock.patch.object(interop_result, "repo_digest", return_value=None):
            doc = rl.convert(work, "2026-10-30T00:00:01Z", WAIVERS)
    doc["summary"] = interop_result.summarize(doc["results"])
    return doc


class Convert(unittest.TestCase):
    def test_a_pass_is_valid_and_passes(self):
        doc = convert(line("cross.browse", "pass"))
        self.assertEqual(interop_result.schema_errors(doc), [])
        self.assertEqual(interop_result.problems(doc), [])
        self.assertEqual(doc["reproduce"], "REPORT_DIR=reports smoke.sh cross")
        self.assertEqual(len(doc["implementations"]), 2)

    def test_zero_passes_fail(self):
        self.assertTrue(interop_result.problems(convert()))
        self.assertTrue(interop_result.problems(convert(line("cross.browse", "known-difference", "x", "w"))))

    def test_known_difference_is_not_a_pass_but_passes_the_run(self):
        doc = convert(line("cross.browse", "pass"), line("cross.call", "known-difference", "x", "w"))
        self.assertEqual(interop_result.schema_errors(doc), [])
        self.assertEqual(doc["summary"]["pass"], 1)
        self.assertTrue(doc["waivers"][0]["reproduced"])
        self.assertEqual(interop_result.problems(doc), [])

    def test_stale_waiver_fails(self):
        doc = convert(line("cross.browse", "pass"), line("cross.call", "fail", "gone", "w"))
        self.assertFalse(doc["waivers"][0]["reproduced"])
        self.assertTrue(interop_result.problems(doc))

    def test_infra_error_fails(self):
        self.assertTrue(interop_result.problems(convert(line("cross.a", "pass"), line("cross.harness", "infra-error", "x"))))

    def test_unknown_waiver_stops(self):
        with self.assertRaises(SystemExit):
            convert(line("cross.call", "known-difference", "x", "other"))

    def test_known_difference_needs_a_waiver(self):
        with self.assertRaises(SystemExit):
            convert(line("cross.call", "known-difference", "x"))


class Files(unittest.TestCase):
    def test_every_waiver_the_scripts_name_exists(self):
        names = set()
        for script in ("smoke.sh", "pubsub-smoke.sh"):
            for kind, name in re.findall(r"^\s*(known|stale) ([a-z0-9-]+) ", Path(HERE, script).read_text(), 8):
                names.add(name)
        self.assertEqual(names, set(rl.load_waivers()))

    def test_pins(self):
        self.assertEqual(rl.pins()["open62541"]["version"], "v1.5.9")

    def test_the_scripts_parse(self):
        for script in ("smoke.sh", "pubsub-smoke.sh", "results.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(HERE, script)]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
