"""Offline launcher integrity, bootstrap and signal checks on Linux."""
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"), "Linux Bash launcher")
class LauncherTests(unittest.TestCase):
    def prepare(self, directory):
        work = Path(directory)
        launcher = work / "stealthcat-check.sh"
        launcher.write_bytes((ROOT / launcher.name).read_bytes())
        cache = work / "private-tmp"
        cache.mkdir()
        return work, launcher, {**os.environ, "TMPDIR": str(cache)}

    def test_colocated_pinned_source_runs_from_cleaned_private_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, launcher, env = self.prepare(temporary)
            (work / "stealthcat_check.py").write_bytes((ROOT / "stealthcat_check.py").read_bytes())
            result = subprocess.run(["bash", str(launcher), "--version"], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("1.0.0", result.stdout)
            self.assertEqual(list((work / "private-tmp").iterdir()), [])

    def test_tampered_colocated_file_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, launcher, env = self.prepare(temporary)
            marker = work / "must-not-exist"
            (work / "stealthcat_check.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
            result = subprocess.run(["bash", str(launcher), "--version"], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA256 mismatch", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(list((work / "private-tmp").iterdir()), [])

    def test_standalone_bootstrap_uses_fixed_tls_source_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, launcher, env = self.prepare(temporary)
            tools = work / "tools"
            tools.mkdir()
            curl = tools / "curl"
            curl.write_text("#!/usr/bin/env python3\n"
                            "import os, pathlib, sys\n"
                            "args=sys.argv[1:]\n"
                            "assert args[0]=='--disable'\n"
                            "assert args[args.index('--proto')+1]=='=https'\n"
                            "assert args[args.index('--proto-redir')+1]=='=https'\n"
                            "assert args[-1]=='https://raw.githubusercontent.com/alkafeu/stealthcat-server-check/v1.0.0/stealthcat_check.py'\n"
                            "assert '--insecure' not in args and '-k' not in args\n"
                            "pathlib.Path(args[args.index('--output')+1]).write_bytes(pathlib.Path(os.environ['CHECK_SOURCE']).read_bytes())\n")
            curl.chmod(0o700)
            env.update(PATH=str(tools) + os.pathsep + env["PATH"], CHECK_SOURCE=str(ROOT / "stealthcat_check.py"))
            result = subprocess.run(["bash", str(launcher), "--version"], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("1.0.0", result.stdout)
            self.assertEqual(list((work / "private-tmp").iterdir()), [])

    def test_sigterm_forwarded_to_child_before_temporary_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, launcher, env = self.prepare(temporary)
            ready, stopped = work / "ready", work / "stopped"
            fixture = ("from pathlib import Path\nimport signal, sys, time\n"
                       "def stop(*args):\n    Path(" + repr(str(stopped)) + ").touch()\n    sys.exit(130)\n"
                       "signal.signal(signal.SIGTERM, stop)\n"
                       "Path(" + repr(str(ready)) + ").touch()\ntime.sleep(30)\n").encode()
            original = (ROOT / "stealthcat_check.py").read_bytes()
            launcher.write_text(launcher.read_text().replace(hashlib.sha256(original).hexdigest(), hashlib.sha256(fixture).hexdigest()))
            (work / "stealthcat_check.py").write_bytes(fixture)
            child = subprocess.Popen(["bash", str(launcher)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "Child did not become ready")
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 143, stdout + stderr)
                self.assertTrue(stopped.exists(), "Child did not receive SIGTERM")
                self.assertEqual(list((work / "private-tmp").iterdir()), [])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()


if __name__ == "__main__":
    unittest.main()
