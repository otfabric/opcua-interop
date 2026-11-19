#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of scripts/check-versions.sh on a copy of the tracked files: it fails on a
FROM line without a digest and on an open62541 commit that versions.yaml does not
record."""

import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPEN62541 = os.path.join("adapters", "open62541", "Dockerfile")
RUNTIME_FROM = "FROM ${BASE_REGISTRY}/debian:bookworm-slim@${DEBIAN_DIGEST} AS runtime\n"


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [name for name in out.decode().split("\0") if name]


class CheckVersions(unittest.TestCase):
    def setUp(self):
        files = tracked_files()
        if files is None:
            self.skipTest("git ls-files is not available")
        if shutil.which("jq") is None:
            self.skipTest("check-versions.sh needs jq")
        self.tree = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tree)
        for name in files:
            src = os.path.join(ROOT, name)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(self.tree, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

    def run_check(self):
        return subprocess.run(["bash", os.path.join(self.tree, "scripts", "check-versions.sh")],
                              cwd=self.tree, capture_output=True, text=True)

    def replace(self, name, old, new):
        path = os.path.join(self.tree, name)
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        old_crlf = old.replace("\n", "\r\n")
        if old not in text and old_crlf in text:
            old, new = old_crlf, new.replace("\n", "\r\n")
        self.assertEqual(text.count(old), 1, f"{name}: {old!r}")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text.replace(old, new))

    def test_the_tree_passes(self):
        res = self.run_check()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("ok   every FROM line is pinned by digest", res.stdout)

    def test_a_from_line_without_a_digest_fails(self):
        # The other stages keep the digest, so the set of digests used is unchanged.
        self.replace(OPEN62541, RUNTIME_FROM, "FROM debian:bookworm-slim AS runtime\n")
        res = self.run_check()
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn("FROM debian:bookworm-slim is not pinned by digest", res.stdout)

    def test_an_image_argument_without_a_digest_fails(self):
        self.replace(OPEN62541, RUNTIME_FROM, "ARG RUNTIME_IMAGE=debian:bookworm-slim\nFROM ${RUNTIME_IMAGE} AS runtime\n")
        res = self.run_check()
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn("FROM ${RUNTIME_IMAGE} is not pinned by digest", res.stdout)

    def test_another_open62541_commit_fails(self):
        self.replace(OPEN62541, "ARG OPEN62541_SHA=93c3bdfc9ea4718b503c6cbf57876237addd0f2c\n",
                     "ARG OPEN62541_SHA=0000000000000000000000000000000000000000\n")
        res = self.run_check()
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn("is not ARG OPEN62541_SHA", res.stdout)


if __name__ == "__main__":
    unittest.main()
