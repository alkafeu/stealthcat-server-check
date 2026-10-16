"""Offline unit checks. No Internet, Docker daemon, or installed OpenSSL required."""
import contextlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stealthcat_check", ROOT / "stealthcat_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def container(*, running=True, health=None, restarts=0):
    return {"id": "test-id", "name": "/example", "image": "sha256:example",
            "restarts": restarts, "running": running, "oom": False,
            "startedAt": "2026-01-01T00:00:00Z", "health": health}


class ServiceTests(unittest.TestCase):
    def test_missing_docker_is_unknown_not_unhealthy(self):
        with mock.patch.object(check.shutil, "which", return_value=None):
            snapshot = check.containers()
        result = check.compare_services(snapshot, snapshot)
        self.assertEqual(snapshot["reason"], "docker_not_installed")
        self.assertIsNone(result["unchanged"])
        self.assertIsNone(result["runningServicesHealthyAfter"])
        self.assertEqual(result["status"], "unavailable")

    def test_docker_access_denied_is_unknown(self):
        with mock.patch.object(check.shutil, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(check, "command", return_value={"code": 1, "stdout": ""}):
            snapshot = check.containers()
        self.assertFalse(snapshot["readable"])
        self.assertEqual(snapshot["reason"], "docker_access_unavailable")

    def test_no_healthcheck_is_healthy_running_service(self):
        before = {"readable": True, "containers": [container(health=None)]}
        self.assertTrue(check.compare_services(before, before)["runningServicesHealthyAfter"])
        with mock.patch.object(check.shutil, "which", return_value="docker"), \
             mock.patch.object(check, "command", side_effect=[
                 {"code": 0, "stdout": "test-id\n"},
                 {"code": 0, "stdout": json.dumps(container(health=None)) + "\n"}]):
            result = check.containers()
        self.assertTrue(result["readable"])
        self.assertIsNone(result["containers"][0]["health"])

    def test_restart_stop_new_container_detected(self):
        before = {"readable": True, "containers": [container()]}
        for item in (container(restarts=1), container(running=False), container(health="unhealthy")):
            after = {"readable": True, "containers": [item]}
            self.assertFalse(check.compare_services(before, after)["unchanged"])
        added = container()
        added["id"] = "new-id"
        self.assertFalse(check.compare_services(before, {"readable": True, "containers": [container(), added]})["unchanged"])

    def test_stopped_container_remains_stopped_without_false_alarm(self):
        state = {"readable": True, "containers": [container(running=False)]}
        result = check.compare_services(state, state)
        self.assertEqual(result["status"], "unchanged")
        self.assertTrue(result["runningServicesHealthyAfter"])

    def test_starting_healthcheck_is_not_claimed_healthy(self):
        state = {"readable": True, "containers": [container(health="starting")]}
        result = check.compare_services(state, state)
        self.assertIsNone(result["runningServicesHealthyAfter"])
        self.assertTrue(result["runningServicesNotUnhealthyAfter"])
        self.assertEqual(result["pendingHealthchecksAfter"], 1)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.sent = []

    def settimeout(self, value):
        pass

    def connect(self, value):
        pass

    def sendall(self, value):
        self.sent.append(value)

    def send(self, value):
        self.sent.append(value)
        return len(value)

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.offset = 0
        self.read_sizes = []

    def begin(self):
        pass

    def getheader(self, key):
        return self.headers.get(key)

    def read(self, size):
        self.read_sizes.append(size)
        data = self.body[self.offset:self.offset + size]
        self.offset += len(data)
        return data

    def close(self):
        pass


class NetworkTests(unittest.TestCase):
    def request(self, response, *, budget=64, **kwargs):
        fake = FakeSocket()
        context = mock.Mock()
        context.wrap_socket.return_value = fake
        checker = check.NetworkChecks(budget)
        with mock.patch.object(check, "deadline", side_effect=lambda _: contextlib.nullcontext()), \
             mock.patch.object(check.socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]), \
             mock.patch.object(check.socket, "socket", return_value=fake), \
             mock.patch.object(check.ssl, "create_default_context", return_value=context), \
             mock.patch.object(check.http.client, "HTTPResponse", return_value=response):
            result = checker.request("example.org", "/", **kwargs)
        return checker, result, fake, context

    def test_ignored_range_does_not_download_body(self):
        response = FakeResponse(status=200, body=b"x" * 1000)
        checker, result, _, _ = self.request(response, limit=8, require_range=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "range_not_honoured_no_body_downloaded")
        self.assertEqual(response.read_sizes, [])
        self.assertEqual(checker.download_bytes, 0)

    def test_wrong_content_range_does_not_download_body(self):
        response = FakeResponse(status=206, headers={"Content-Range": "bytes 0-15/100"}, body=b"x" * 16)
        _, result, _, _ = self.request(response, limit=8, require_range=True)
        self.assertFalse(result["ok"])
        self.assertEqual(response.read_sizes, [])

    def test_range_and_exact_read_cap_with_verified_tls(self):
        response = FakeResponse(status=206, headers={"Content-Range": "bytes 0-7/100"}, body=b"x" * 100)
        checker, result, fake, context = self.request(response, limit=8, require_range=True)
        self.assertTrue(result["ok"])
        self.assertEqual(response.offset, 8)
        self.assertEqual(checker.download_bytes, 8)
        self.assertTrue(result["tlsVerified"])
        context.wrap_socket.assert_called_once_with(fake, server_hostname="example.org")
        self.assertIn(b"Range: bytes=0-7\r\n", fake.sent[0])
        self.assertTrue(fake.closed)

    def test_budget_rejects_before_dns_or_transfer(self):
        checker = check.NetworkChecks(8)
        with mock.patch.object(check.socket, "getaddrinfo") as dns:
            result = checker.request("example.org", "/", limit=9)
        self.assertEqual(result["reason"], "body_budget_exceeded")
        dns.assert_not_called()

    def test_upload_counts_exact_body(self):
        response = FakeResponse(status=200)
        checker, result, _, _ = self.request(response, method="POST", payload_size=8)
        self.assertEqual(checker.upload_bytes, 8)
        self.assertEqual(result["sentBodyBytes"], 8)
        self.assertTrue(result["ok"])

    def test_reachability_401_is_not_geographic_diagnosis(self):
        response = FakeResponse(status=401)
        _, result, _, _ = self.request(response, method="HEAD")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 401)
        self.assertEqual(response.read_sizes, [])

    def test_dns_timeout_recorded_without_retry(self):
        checker = check.NetworkChecks(8)
        with mock.patch.object(check, "deadline", side_effect=lambda _: contextlib.nullcontext()), \
             mock.patch.object(check.socket, "getaddrinfo", side_effect=TimeoutError) as dns:
            result = checker.request("example.org", "/", limit=8)
        self.assertEqual(result["errorType"], "TimeoutError")
        self.assertEqual(dns.call_count, 1)

    def test_profile_maximum_body_schedule(self):
        for profile, maximum in (("default", 40 * check.MIB), ("quick", 16 * check.MIB)):
            checker = check.NetworkChecks(maximum)
            scheduled = []
            def request(host, path, **kwargs):
                scheduled.append(kwargs.get("limit", 0) + kwargs.get("payload_size", 0))
                return {"ok": True}
            with mock.patch.object(checker, "request", side_effect=request):
                checker.run(profile, ipv6=True)
            self.assertEqual(sum(scheduled), maximum)


class ResourceTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux deadline signal")
    def test_stage_deadline_interrupts_blocking_work_and_restores_handler(self):
        import signal
        before = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with check.deadline(0.02):
                time.sleep(0.2)
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_low_memory_does_not_allocate_ram(self):
        with mock.patch.object(check, "memory", return_value={"effectiveAvailableBytes": 128 * check.MIB}), \
             mock.patch.object(check.mmap, "mmap") as allocate:
            result = check.ram_copy()
        self.assertTrue(result["skipped"])
        allocate.assert_not_called()

    def test_tmpfs_skipped_before_scratch_creation(self):
        with mock.patch.object(check, "memory", return_value={"effectiveAvailableBytes": 512 * check.MIB}), \
             mock.patch.object(check.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(4 * 1024 ** 3, 0, 4 * 1024 ** 3)), \
             mock.patch.object(check, "command", return_value={"code": 0, "stdout": "tmpfs\n"}), \
             mock.patch.object(check.tempfile, "mkdtemp") as make:
            if not hasattr(os, "O_DIRECT"):
                self.skipTest("Linux direct I/O only")
            result = check.disk_tests(Path(tempfile.gettempdir()))
        self.assertEqual(result["reason"], "scratch_is_memory_filesystem")
        make.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux SIGTERM cleanup")
    def test_sigterm_removes_scratch_and_preserves_unrelated_file(self):
        # Isolated child, 4MiB temporary data only; no network or real Docker.
        with tempfile.TemporaryDirectory() as temporary:
            keep = Path(temporary) / "keep.txt"
            keep.write_text("keep")
            script = r'''
import importlib.util, os, pathlib, signal, sys
from unittest import mock
spec=importlib.util.spec_from_file_location("check", sys.argv[1]); check=importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
def stop(*args): raise check.Cancelled()
signal.signal(signal.SIGTERM, stop)
real_open=os.open
def local_open(path, flags, mode=0o777, **kwargs): return real_open(path, flags & ~os.O_DIRECT, mode, **kwargs)
def write(*args):
    # The Python fixture traceback must not retain an exported mmap view either.
    del args
    os.kill(os.getpid(), signal.SIGTERM)
# Use a plain replacement: Mock call history would retain the memoryview and
# create an artificial BufferError while mmap closes during signal unwinding.
with mock.patch.object(check,"memory",return_value={"effectiveAvailableBytes":512*check.MIB}), mock.patch.object(check,"command",return_value={"code":0,"stdout":"ext4"}), mock.patch.object(check.shutil,"disk_usage",return_value=check.shutil._ntuple_diskusage(4*1024**3,0,4*1024**3)), mock.patch.object(check.os,"open",side_effect=local_open), mock.patch.object(check.os,"pwrite",new=write):
    try: check.disk_tests(pathlib.Path(sys.argv[2]),size=4*check.MIB)
    except check.Cancelled: pass
    else: raise AssertionError("SIGTERM not received")
assert list(pathlib.Path(sys.argv[2]).iterdir())==[pathlib.Path(sys.argv[2])/"keep.txt"]
'''
            result = subprocess.run([sys.executable, "-c", script, str(ROOT / "stealthcat_check.py"), temporary],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(keep.read_text(), "keep")


class ReportTests(unittest.TestCase):
    def test_json_markdown_csv_written_and_not_clobbered(self):
        report = {"startedAtUtc": "test", "finishedAtUtc": "test", "profile": "quick", "exitCode": 0,
                  "serviceIntegrity": {"status": "unavailable"},
                  "traffic": {"downloadBodyBytes": 0, "uploadBodyBytes": 0}}
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            check.write_reports(folder, report)
            self.assertEqual(json.loads((folder / "report.json").read_text())["profile"], "quick")
            self.assertIn("Service integrity: **unavailable**", (folder / "report.md").read_text())
            self.assertTrue((folder / "measurements.csv").read_text().startswith("group,measurement,unit,value,ok"))
            with self.assertRaises(FileExistsError):
                check.write_reports(folder, report)

    def test_cli_help_and_version_have_no_measurements(self):
        for flag in ("--help", "--version"):
            result = subprocess.run([sys.executable, str(ROOT / "stealthcat_check.py"), flag],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(check.VERSION, result.stdout)


if __name__ == "__main__":
    unittest.main()
