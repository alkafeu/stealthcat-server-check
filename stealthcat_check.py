#!/usr/bin/env python3
"""Small, bounded Linux VPS checks. Python standard library; no package installation.

Reports stay local. No service restarts, firewall/sysctl changes or cache drops.
Network byte limits cover application bodies, not DNS/TLS/TCP overhead.
"""
import argparse
import contextlib
import csv
import ctypes
from datetime import datetime, timezone
import errno
import gc
import hashlib
import http.client
import io
import json
import mmap
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

VERSION = "1.0.0"
MIB = 1024 * 1024
USER_AGENT = "StealthCat-server-check/" + VERSION


class Cancelled(BaseException):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def command(args, timeout=8):
    """Never use a shell, or return arbitrary stderr which might contain secrets."""
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout, env={**os.environ, "LC_ALL": "C"})
        return {"code": result.returncode, "stdout": result.stdout}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"code": None, "stdout": "", "errorType": type(exc).__name__}


def read_number(path):
    try:
        value = Path(path).read_text().strip()
        return None if value == "max" else int(value)
    except (OSError, ValueError):
        return None


def memory():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        return {"readable": False, "effectiveAvailableBytes": 0}
    available = values.get("MemAvailable", 0)
    cgroup_limit = cgroup_used = None
    for limit_path, used_path in [
        ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"),
    ]:
        limit = read_number(limit_path)
        used = read_number(used_path)
        if limit is not None and used is not None and 0 < limit < (1 << 60):
            available = min(available, max(0, limit - used))
            cgroup_limit, cgroup_used = limit, used
            break
    return {"readable": True, **{k: values.get(k, 0) for k in
            ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")},
            "effectiveAvailableBytes": available,
            "cgroupLimitBytes": cgroup_limit, "cgroupUsedBytes": cgroup_used}


def pressure():
    result = {}
    for name in ("cpu", "memory", "io"):
        try:
            result[name] = {line.split()[0]: {
                key: float(value) for key, value in
                (token.split("=", 1) for token in line.split()[1:])
                if key.startswith("avg")}
                for line in (Path("/proc/pressure") / name).read_text().splitlines()}
        except (OSError, ValueError):
            pass
    return result


def containers():
    if not shutil.which("docker"):
        return {"readable": False, "reason": "docker_not_installed", "containers": []}
    listed = command(["docker", "ps", "-aq"])
    if listed["code"] != 0:
        return {"readable": False, "reason": "docker_access_unavailable", "containers": []}
    ids = listed["stdout"].split()
    if not ids:
        return {"readable": True, "containers": []}
    template = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                '"restarts":{{json .RestartCount}},"running":{{json .State.Running}},'
                '"oom":{{json .State.OOMKilled}},"startedAt":{{json .State.StartedAt}},'
                '"health":{{if index .State "Health"}}{{json (index .State "Health" "Status")}}{{else}}null{{end}}}')
    inspected = command(["docker", "inspect", "--format", template, *ids], timeout=12)
    if inspected["code"] != 0:
        return {"readable": False, "reason": "docker_inspect_unavailable", "containers": []}
    try:
        items = [json.loads(line) for line in inspected["stdout"].splitlines() if line.strip()]
        if len(items) != len(ids) or len({item["id"] for item in items}) != len(ids):
            raise ValueError("incomplete_docker_inspection")
        return {"readable": True, "containers": sorted(items, key=lambda item: item["id"])}
    except (ValueError, KeyError, TypeError):
        return {"readable": False, "reason": "docker_output_unreadable", "containers": []}


def snapshot(scratch_dir, check_services=True):
    disk = shutil.disk_usage(scratch_dir)
    try:
        load = list(os.getloadavg())
    except OSError:
        load = None
    return {"atUtc": utc_now(), "load": load, "vcpus": os.cpu_count() or 1,
            "memory": memory(), "pressure": pressure(),
            "disk": {"total": disk.total, "free": disk.free},
            "docker": containers() if check_services else
            {"readable": False, "reason": "disabled", "containers": []}}


def compare_services(before, after):
    """Unknown is not false health. Check only services running before the test."""
    if not before.get("readable") or not after.get("readable"):
        return {"status": "unavailable", "unchanged": None,
                "runningServicesHealthyAfter": None,
                "reason": "docker_snapshot_unavailable"}
    old = {item["id"]: item for item in before["containers"]}
    new = {item["id"]: item for item in after["containers"]}
    running = [item for item in old.values() if item["running"]]
    not_unhealthy = all(item["id"] in new and new[item["id"]]["running"]
                  and not new[item["id"]]["oom"]
                  and new[item["id"]]["health"] != "unhealthy" for item in running)
    pending = sum(item["id"] in new and new[item["id"]]["health"] == "starting" for item in running)
    healthy = None if pending and not_unhealthy else not_unhealthy
    unchanged = old == new
    return {"status": "unchanged" if unchanged and not_unhealthy else "changed_or_unhealthy",
            "unchanged": unchanged, "runningServicesHealthyAfter": healthy,
            "runningServicesNotUnhealthyAfter": not_unhealthy,
            "pendingHealthchecksAfter": pending,
            "checkedRunningContainers": len(running), "checkedTotalContainers": len(old)}


def cpu_tests():
    if not shutil.which("openssl"):
        return {"skipped": True, "reason": "openssl_not_installed", "results": []}
    tests = []
    for label, args in [("sha256", ["sha256"]),
                        ("aes-128-gcm", ["-evp", "aes-128-gcm", "-aead"]),
                        ("chacha20-poly1305", ["-evp", "chacha20-poly1305", "-aead"])]:
        started = time.monotonic()
        result = command(["openssl", "speed", "-elapsed", "-seconds", "3", "-bytes", "16384", *args], 15)
        rows = []
        for line in result["stdout"].splitlines():
            pieces = line.split()
            if pieces and pieces[0].lower() == label and re.fullmatch(r"[0-9.]+k?", pieces[-1]):
                token = pieces[-1]
                rows.append(float(token.rstrip("k")) * (1000 if token.endswith("k") else 1))
        tests.append({"algorithm": label, "ok": result["code"] == 0 and bool(rows),
                      "bytesPerSecond": rows[-1] if result["code"] == 0 and rows else None,
                      "wallSeconds": time.monotonic() - started, "blockBytes": 16384,
                      "secondsPerAlgorithm": 3, "singleWorker": True,
                      "errorType": result.get("errorType")})
    return {"results": tests}


def ram_copy():
    if memory()["effectiveAvailableBytes"] < 256 * MIB:
        return {"skipped": True, "reason": "less_than_256MiB_available"}
    size = 32 * MIB
    with mmap.mmap(-1, size) as source, mmap.mmap(-1, size) as destination:
        source[:] = b"X" * size
        src = ctypes.addressof(ctypes.c_char.from_buffer(source))
        dst = ctypes.addressof(ctypes.c_char.from_buffer(destination))
        ctypes.memmove(dst, src, size)
        started, repeats = time.monotonic(), 0
        while repeats < 32 and time.monotonic() - started < 0.5:
            ctypes.memmove(dst, src, size)
            repeats += 1
        elapsed = time.monotonic() - started
    return {"ok": True, "bufferBytes": size, "copies": repeats,
            "copiedBytes": size * repeats, "wallSeconds": elapsed,
            "bytesPerSecond": size * repeats / elapsed,
            "note": "Warm 32MiB memcpy sample; cache/CPU dependent, not STREAM bandwidth"}


def alarm_handler(_signum, _frame):
    raise TimeoutError("stage_deadline")


@contextlib.contextmanager
def deadline(seconds):
    old_handler = signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def disk_tests(scratch_dir, size=64 * MIB):
    if memory()["effectiveAvailableBytes"] < 256 * MIB or shutil.disk_usage(scratch_dir).free < 1024 * MIB:
        return {"skipped": True, "reason": "scratch_resource_guard"}
    if not all(hasattr(os, name) for name in ("O_DIRECT", "preadv", "pwrite")):
        return {"skipped": True, "reason": "direct_io_unavailable"}
    fs = command(["findmnt", "-n", "-o", "FSTYPE", "--target", str(scratch_dir)])
    fstype = fs["stdout"].strip()
    if not fstype:
        return {"skipped": True, "reason": "filesystem_type_unavailable"}
    if fstype in {"tmpfs", "ramfs"}:
        return {"skipped": True, "reason": "scratch_is_memory_filesystem"}
    scratch = None
    fd = None
    result = {"scratchBytes": size, "directIo": True, "queueDepth": 1, "filesystem": fstype}
    try:
        scratch = Path(tempfile.mkdtemp(prefix="stealthcat-check-", dir=scratch_dir))
        os.chmod(scratch, 0o700)
        filename = scratch / "scratch.bin"
        with mmap.mmap(-1, size) as data:
            for offset in range(0, size, 4 * MIB):
                data[offset:offset + 4 * MIB] = os.urandom(4 * MIB)
            fd = os.open(str(filename), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_DIRECT, 0o600)
            with deadline(10):
                begin = time.monotonic()
                view = memoryview(data)
                try:
                    for offset in range(0, size, MIB):
                        if os.pwrite(fd, view[offset:offset + MIB], offset) != MIB:
                            raise OSError("short_write")
                    data_elapsed = time.monotonic() - begin
                    sync_start = time.monotonic()
                    os.fdatasync(fd)
                    sync_elapsed = time.monotonic() - sync_start
                finally:
                    view.release()
            result["sequentialWrite"] = {"bytes": size, "dataSeconds": data_elapsed,
                "syncSeconds": sync_elapsed, "bytesPerSecondIncludingSync": size / (data_elapsed + sync_elapsed)}
        gc.collect()
        with mmap.mmap(-1, MIB) as block, deadline(10):
            begin = time.monotonic()
            for offset in range(0, size, MIB):
                if os.preadv(fd, [block], offset) != MIB:
                    raise OSError("short_read")
            elapsed = time.monotonic() - begin
            result["sequentialRead"] = {"bytes": size, "seconds": elapsed, "bytesPerSecond": size / elapsed}
        randomizer = random.Random(1)
        with mmap.mmap(-1, 4096) as block:
            for write in (False, True):
                if write:
                    block[:] = os.urandom(4096)
                with deadline(5):
                    started, operations = time.monotonic(), 0
                    maximum = 1024 if write else 4096
                    while operations < maximum and time.monotonic() - started < 2:
                        offset = randomizer.randrange(size // 4096) * 4096
                        if write:
                            block[:8] = operations.to_bytes(8, "little")
                        count = os.pwrite(fd, block, offset) if write else os.preadv(fd, [block], offset)
                        if count != 4096:
                            raise OSError("short_random_io")
                        operations += 1
                    data_elapsed = time.monotonic() - started
                    sync_start = time.monotonic()
                    if write:
                        os.fdatasync(fd)
                    sync_elapsed = time.monotonic() - sync_start if write else 0
                result["randomWrite" if write else "randomRead"] = {
                    "blockBytes": 4096, "operations": operations, "bytes": operations * 4096,
                    "dataSeconds": data_elapsed, "syncSeconds": sync_elapsed,
                    "iopsIncludingSync": operations / (data_elapsed + sync_elapsed)}
        result["ok"] = True
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.EOPNOTSUPP, errno.ENOSYS}:
            result.update(skipped=True, reason="filesystem_does_not_support_direct_io", errorCode=exc.errno)
        else:
            result.update(ok=False, errorType=type(exc).__name__, errorCode=exc.errno)
    except Exception as exc:
        result.update(ok=False, errorType=type(exc).__name__)
    finally:
        if fd is not None:
            os.close(fd)
        if scratch is not None:
            # Only the newly-created unique directory; no caller-controlled recursive target.
            shutil.rmtree(scratch)
            result["scratchRemoved"] = not scratch.exists()
    return result


class NetworkChecks:
    def __init__(self, body_budget):
        self.body_budget = body_budget
        self.download_bytes = 0
        self.upload_bytes = 0

    def request(self, host, path, *, family=socket.AF_INET, method="GET", limit=0,
                payload_size=0, require_range=False):
        started = time.monotonic()
        info = {"host": host, "method": method, "family": 4 if family == socket.AF_INET else 6,
                "requestedBodyBytes": limit if method == "GET" else payload_size,
                "sentBodyBytes": 0, "receivedBodyBytes": 0}
        if limit < 0 or payload_size < 0 or limit + payload_size + self.download_bytes + self.upload_bytes > self.body_budget:
            return {**info, "ok": False, "reason": "body_budget_exceeded"}
        raw = tls = response = None
        try:
            with deadline(6 if method == "HEAD" else 16):
                begin = time.monotonic()
                addresses = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
                info["dnsMs"] = (time.monotonic() - begin) * 1000
                address = addresses[0]
                raw = socket.socket(address[0], address[1], address[2])
                raw.settimeout(4)
                begin = time.monotonic()
                raw.connect(address[4])
                info["tcpMs"] = (time.monotonic() - begin) * 1000
                begin = time.monotonic()
                tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                info.update(tlsMs=(time.monotonic() - begin) * 1000, tlsVerified=True)
                tls.settimeout(5)
                fields = {"Host": host, "User-Agent": USER_AGENT, "Connection": "close", "Accept-Encoding": "identity"}
                if require_range:
                    fields["Range"] = "bytes=0-" + str(limit - 1)
                if payload_size:
                    fields.update({"Content-Length": str(payload_size), "Content-Type": "application/octet-stream"})
                wire = method + " " + path + " HTTP/1.1\r\n" + "".join(k + ": " + v + "\r\n" for k, v in fields.items()) + "\r\n"
                tls.sendall(wire.encode("ascii"))
                sent_start = time.monotonic()
                if payload_size:
                    block, remaining = os.urandom(65536), payload_size
                    while remaining:
                        if time.monotonic() - sent_start > 12:
                            raise TimeoutError("upload_deadline")
                        count = tls.send(block[:min(remaining, len(block))])
                        if count <= 0:
                            raise ConnectionError("upload_closed")
                        self.upload_bytes += count
                        info["sentBodyBytes"] += count
                        remaining -= count
                    info["uploadSendSeconds"] = time.monotonic() - sent_start
                response = http.client.HTTPResponse(tls)
                response.begin()
                info.update(status=response.status, headerWaitMs=(time.monotonic() - sent_start) * 1000)
                encoding = response.getheader("Content-Encoding")
                if encoding and encoding.lower() != "identity":
                    return {**info, "ok": False, "reason": "unexpected_content_encoding_no_body_downloaded"}
                content_range = re.fullmatch(r"bytes 0-([0-9]+)/([0-9]+)", response.getheader("Content-Range") or "")
                if require_range and (response.status != 206 or not content_range or
                    int(content_range[1]) != limit - 1 or int(content_range[2]) < limit):
                    return {**info, "ok": False, "reason": "range_not_honoured_no_body_downloaded"}
                if method == "GET" and response.status not in (200, 206):
                    return {**info, "ok": False, "reason": "http_error_no_body_downloaded"}
                begin = time.monotonic()
                while info["receivedBodyBytes"] < limit:
                    if time.monotonic() - begin > 12:
                        raise TimeoutError("download_deadline")
                    piece = response.read(min(65536, limit - info["receivedBodyBytes"]))
                    if not piece:
                        break
                    self.download_bytes += len(piece)
                    info["receivedBodyBytes"] += len(piece)
                elapsed = time.monotonic() - begin
                info["bodySeconds"] = elapsed
                if method == "GET" and limit:
                    info.update(downloadBytesPerSecond=info["receivedBodyBytes"] / elapsed if elapsed else None,
                                ok=info["receivedBodyBytes"] == limit)
                elif payload_size:
                    elapsed = time.monotonic() - sent_start
                    info.update(uploadAckSeconds=elapsed, uploadBytesPerSecond=payload_size / elapsed if elapsed else None,
                                ok=response.status == 200)
                else:
                    info["ok"] = True
                return info
        except Exception as exc:
            info.update(ok=False, errorType=type(exc).__name__)
            return info
        finally:
            info["totalSeconds"] = time.monotonic() - started
            if response is not None:
                response.close()
            if tls is not None:
                tls.close()
            elif raw is not None:
                raw.close()

    def run(self, profile, ipv6=False, upload=True):
        size = (4 if profile == "quick" else 8) * MIB
        repetitions = 1 if profile == "quick" else 2
        result = {"downloads": [], "uploads": [], "httpReachability": []}
        for _ in range(repetitions):
            result["downloads"].append(self.request("speed.cloudflare.com", "/__down?bytes=" + str(size), limit=size))
        result["downloads"].append(self.request("fsn1-speed.hetzner.com", "/100MB.bin", limit=size, require_range=True))
        if ipv6:
            result["downloads"].append(self.request("speed.cloudflare.com", "/__down?bytes=" + str(size), family=socket.AF_INET6, limit=size))
        if upload:
            result["uploads"].append(self.request("speed.cloudflare.com", "/__up", method="POST", payload_size=size))
        for host, path in [("api.telegram.org", "/"), ("api.github.com", "/"),
                           ("registry-1.docker.io", "/v2/"), ("api.openai.com", "/v1/models")]:
            result["httpReachability"].append(self.request(host, path, method="HEAD"))
        result["httpStatusMeaning"] = "TLS/HTTP reachability only. 401/403 do not prove account access or a geographic block."
        result["ipv6Requested"] = ipv6
        return result


def lower_priority():
    result = {"cpuNice": None, "ioIdle": None}
    try:
        os.nice(max(0, 19 - os.getpriority(os.PRIO_PROCESS, 0)))
        result["cpuNice"] = os.getpriority(os.PRIO_PROCESS, 0)
    except OSError:
        pass
    if shutil.which("ionice"):
        result["ioIdle"] = command(["ionice", "-c", "3", "-p", str(os.getpid())])["code"] == 0
    return result


def software_info():
    result = {"python": sys.version.split()[0], "kernel": os.uname().release,
              "openssl": command(["openssl", "version"])["stdout"].strip()}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                result["os"] = line.split("=", 1)[1].strip("\"'")
                break
    except OSError:
        pass
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            key, separator, value = line.partition(":")
            if not separator:
                continue
            if key.strip() in {"model name", "Hardware"} and "cpuModel" not in result:
                result["cpuModel"] = value.strip()
            if key.strip() in {"flags", "Features"} and "cpuFeatures" not in result:
                # Only capabilities useful for interpreting crypto results; no IDs.
                result["cpuFeatures"] = sorted(set(value.split()) & {
                    "aes", "pclmulqdq", "avx", "avx2", "sha_ni", "ssse3", "asimd", "pmull", "sha2"})
    except OSError:
        pass
    return result


def markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def measurement_rows(report):
    rows = []
    for item in report.get("cpu", {}).get("results", []):
        rows.append(("cpu", item["algorithm"], "bytes_per_second", item.get("bytesPerSecond"), item.get("ok")))
    ram = report.get("ram", {})
    if "bytesPerSecond" in ram:
        rows.append(("ram", "warm_memcpy", "bytes_per_second", ram["bytesPerSecond"], ram.get("ok")))
    for key in ("sequentialWrite", "sequentialRead", "randomRead", "randomWrite"):
        item = report.get("disk", {}).get(key)
        if item:
            metric = "iopsIncludingSync" if key.startswith("random") else "bytesPerSecondIncludingSync" if key.endswith("Write") else "bytesPerSecond"
            rows.append(("disk", key, "iops" if key.startswith("random") else "bytes_per_second", item.get(metric), report["disk"].get("ok")))
    for direction in ("downloads", "uploads"):
        for index, item in enumerate(report.get("network", {}).get(direction, []), 1):
            metric = "downloadBytesPerSecond" if direction == "downloads" else "uploadBytesPerSecond"
            rows.append(("network", item["host"] + "/ipv" + str(item["family"]) + "/" + direction + "/" + str(index),
                         "bytes_per_second", item.get(metric), item.get("ok")))
    return rows


def render_markdown(report):
    lines = ["# StealthCat server check", "", "Version: " + VERSION,
             "Started (UTC): " + report["startedAtUtc"],
             "Finished (UTC): " + report["finishedAtUtc"],
             "Profile: " + report["profile"], "", "Service integrity: **" + report["serviceIntegrity"]["status"] + "**.",
             "Exit status: " + str(report["exitCode"]) + ". Individual tests may fail or be skipped; inspect report.json.", "",
             "| Group | Measurement | Unit | Value | OK |", "|---|---|---|---:|---|"]
    for group, name, unit, value, ok in measurement_rows(report):
        formatted = "—" if value is None else format(value, ".2f")
        lines.append("| " + " | ".join(markdown_escape(v) for v in (group, name, unit, formatted, ok)) + " |")
    lines.extend(["", "## Skips and errors", ""])
    for name in ("cpu", "ram", "disk", "network"):
        section = report.get(name, {})
        if section.get("skipped") or section.get("errorType"):
            lines.append("- " + name + ": " + markdown_escape(section.get("reason", section.get("errorType"))))
    for name in ("downloads", "uploads", "httpReachability"):
        for item in report.get("network", {}).get(name, []):
            if item.get("ok") is False:
                lines.append("- " + markdown_escape(item["host"]) + ": " + markdown_escape(item.get("reason", item.get("errorType", "request_failed"))))
    traffic = report["traffic"]
    lines.extend(["", "Application bodies: downloaded " + str(traffic["downloadBodyBytes"]) + " bytes; uploaded " + str(traffic["uploadBodyBytes"]) + " bytes.",
                  "DNS/TCP/TLS/HTTP headers and server buffering are additional traffic.", "",
                  "Results are short samples under current load, not an SLA or a sustained stress test.",
                  "HTTP 401/403 show reachability, not account access or evidence of a geographic block.",
                  "Docker unavailable means unknown service integrity; stopped containers are not declared unhealthy.",
                  "Reports can contain local system and container metadata. Review before sharing.", ""])
    return "\n".join(lines)


def write_reports(directory, report):
    contents = {"report.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                "report.md": render_markdown(report)}
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(("group", "measurement", "unit", "value", "ok"))
    writer.writerows(measurement_rows(report))
    contents["measurements.csv"] = buffer.getvalue()
    for name, content in contents.items():
        with (directory / name).open("x", encoding="utf-8", newline="") as handle:
            os.chmod(directory / name, 0o600)
            handle.write(content)


def parser():
    value = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    value.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    value.add_argument("--profile", choices=("quick", "default"), default="default",
                       help="default: <=40MiB bodies with --ipv6; quick: <=16MiB. CPU stays single-worker, 3s/algorithm")
    value.add_argument("--output-dir", type=Path, help="new report directory; default ./stealthcat-check-<UTC timestamp>")
    value.add_argument("--scratch-dir", type=Path, default=Path("/var/tmp"), help="existing writable directory for a removable 64MiB file (default /var/tmp)")
    for name in ("network", "cpu", "ram", "disk", "services"):
        value.add_argument("--no-" + name, action="store_true", help="skip " + name + " checks")
    value.add_argument("--no-upload", action="store_true", help="omit the bounded synthetic network upload")
    value.add_argument("--ipv6", action="store_true", help="also run one bounded IPv6 Cloudflare download")
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    if not sys.platform.startswith("linux"):
        print("Runtime checks require Linux. --help and --version work on other platforms.", file=sys.stderr)
        return 2
    if not args.scratch_dir.is_dir():
        print("Scratch directory does not exist.", file=sys.stderr)
        return 2
    output_dir = args.output_dir or Path("stealthcat-check-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    try:
        output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        print("Cannot create new output directory: " + type(exc).__name__, file=sys.stderr)
        return 2
    previous_handlers = {}
    def cancel(_signum, _frame):
        raise Cancelled()
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.signal(sig, cancel)
    report = {"schemaVersion": 1, "version": VERSION, "profile": args.profile, "startedAtUtc": utc_now(),
              "serviceIntegrity": {"status": "unavailable", "unchanged": None, "runningServicesHealthyAfter": None}}
    checker = NetworkChecks(40 * MIB if args.profile == "default" else 16 * MIB)
    exit_code = 0
    try:
        report["priority"] = lower_priority()
        report["software"] = software_info()
        report["before"] = snapshot(args.scratch_dir, not args.no_services)
        load = report["before"]["load"]
        overloaded = load is not None and load[0] / report["before"]["vcpus"] > 1.5
        for name, work in (("cpu", cpu_tests), ("ram", ram_copy), ("disk", lambda: disk_tests(args.scratch_dir))):
            if getattr(args, "no_" + name):
                report[name] = {"skipped": True, "reason": "disabled"}
            elif overloaded:
                report[name] = {"skipped": True, "reason": "load_guard"}
            else:
                print("Checking " + name + "...", file=sys.stderr, flush=True)
                try:
                    report[name] = work()
                except Exception as exc:
                    report[name] = {"ok": False, "errorType": type(exc).__name__}
        if args.no_network:
            report["network"] = {"skipped": True, "reason": "disabled"}
        else:
            print("Checking network (bounded HTTPS bodies)...", file=sys.stderr, flush=True)
            report["network"] = checker.run(args.profile, args.ipv6, not args.no_upload)
    except Cancelled:
        exit_code = 130
        report["interrupted"] = True
    except Exception as exc:
        exit_code = 1
        report["errorType"] = type(exc).__name__
    finally:
        # Ignore a second Ctrl-C while preserving partial reports and service checks.
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            report["after"] = snapshot(args.scratch_dir, not args.no_services)
            if "before" in report:
                report["serviceIntegrity"] = compare_services(report["before"]["docker"], report["after"]["docker"])
                if report["serviceIntegrity"]["status"] == "changed_or_unhealthy" and not exit_code:
                    exit_code = 3
        except Exception as exc:
            report["afterSnapshotErrorType"] = type(exc).__name__
            if not exit_code:
                exit_code = 1
        report.update(finishedAtUtc=utc_now(), exitCode=exit_code,
                      traffic={"downloadBodyBytes": checker.download_bytes, "uploadBodyBytes": checker.upload_bytes,
                               "maximumBodyBytes": checker.body_budget},
                      scope={"packagesInstalled": False, "serviceRestarts": False, "firewallOrSysctlChanges": False,
                             "publicReportUpload": False, "scratchMaximumBytes": 64 * MIB,
                             "cpuMaximumWorkers": 1, "diskQueueDepth": 1})
        try:
            write_reports(output_dir, report)
            print("Reports: " + str(output_dir.resolve()), flush=True)
        except OSError as exc:
            print("Cannot save report: " + type(exc).__name__, file=sys.stderr)
            exit_code = 1
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
