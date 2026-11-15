#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of the digest step of .github/workflows/release.yml and of
scripts/check-digests.sh: a release gets one sha256 digest for every adapter, or
the step fails."""

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEP = "Digests of the multi-arch images"


def adapters():
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("ADAPTERS ?= "):
                return line.split("?=", 1)[1].split()
    raise AssertionError("no ADAPTERS in the Makefile")


def digest_step():
    """The shell and the run script of the step, as GitHub runs them."""
    with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as f:
        lines = f.read().replace("\r\n", "\n").split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {STEP}")
    indent = len(lines[start]) - len(lines[start].lstrip())
    step = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        step.append(line)
    shell = next((line.split(":", 1)[1].strip() for line in step if line.strip().startswith("shell:")), None)
    run_at = next(i for i, line in enumerate(step) if line.strip() == "run: |")
    body = step[run_at + 1:]
    width = min(len(line) - len(line.lstrip()) for line in body if line.strip())
    script = "\n".join(line[width:] for line in body) + "\n"
    # GitHub's commands: shell bash is `bash --noprofile --norc -eo pipefail {0}`;
    # without a shell, a Linux runner uses `bash -e {0}`.
    command = ["bash", "--noprofile", "--norc", "-eo", "pipefail"] if shell == "bash" else ["bash", "-e"]
    return command, script


def line(adapter, digest=None):
    if digest is None:
        digest = "sha256:" + hashlib.sha256(adapter.encode()).hexdigest()
    return f"{adapter} {digest}\n"


class DigestStep(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work)
        os.makedirs(os.path.join(self.work, "scripts"))
        shutil.copy2(os.path.join(ROOT, "Makefile"), self.work)
        shutil.copy2(os.path.join(ROOT, "scripts", "check-digests.sh"), os.path.join(self.work, "scripts"))
        self.bin = os.path.join(self.work, "bin")
        os.makedirs(self.bin)

    def run_step(self, output, make_exit=0):
        """Runs the step with a make that prints output and exits with make_exit."""
        make = os.path.join(self.bin, "make")
        with open(make, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\ncat <<'EOF'\n" + output + "EOF\nexit " + str(make_exit) + "\n")
        os.chmod(make, os.stat(make).st_mode | stat.S_IXUSR)
        command, script = digest_step()
        with open(os.path.join(self.work, "step.sh"), "w", encoding="utf-8") as f:
            f.write(script)
        github_output = os.path.join(self.work, "github-output")
        open(github_output, "w").close()
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], GITHUB_OUTPUT=github_output, VERSION="v0.0.0")
        res = subprocess.run(command + ["step.sh"], cwd=self.work, env=env, capture_output=True, text=True)
        with open(github_output, encoding="utf-8") as f:
            return res, f.read()

    def test_every_adapter_with_a_digest_passes(self):
        res, outputs = self.run_step("".join(line(a) for a in adapters()))
        self.assertEqual(res.returncode, 0, res.stderr)
        got = dict(entry.split("=", 1) for entry in outputs.split())
        self.assertEqual(sorted(got), sorted(adapters()))
        self.assertTrue(all(re.fullmatch(r"sha256:[0-9a-f]{64}", d) for d in got.values()))

    def test_a_make_that_stops_partway_fails(self):
        res, _ = self.run_step("".join(line(a) for a in adapters()[:3]), make_exit=1)
        self.assertNotEqual(res.returncode, 0, res.stdout)

    def test_a_missing_adapter_fails(self):
        res, outputs = self.run_step("".join(line(a) for a in adapters()[:-1]))
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn(f"{adapters()[-1]}: 0 lines", res.stderr)
        self.assertEqual(outputs, "")

    def test_an_empty_digest_fails(self):
        res, _ = self.run_step("".join(line(a, "" if i == 1 else None) for i, a in enumerate(adapters())))
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn(f"no digest for {adapters()[1]}", res.stderr)

    def test_a_repeated_or_unknown_adapter_fails(self):
        complete = "".join(line(a) for a in adapters())
        for extra in (line(adapters()[0]), line("nonesuch")):
            res, _ = self.run_step(complete + extra)
            self.assertNotEqual(res.returncode, 0, extra)


if __name__ == "__main__":
    unittest.main()
