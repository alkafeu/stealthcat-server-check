#!/usr/bin/env bash
# StealthCat server check v1.0.0. No package installation and no automatic uploads.
# Copy the colocated Python file, or download ONLY the pinned v1.0.0 file below,
# into a private directory. Verify its SHA256, run the copy, then remove it.
set -euo pipefail

readonly VERSION='1.0.0'
readonly SOURCE_URL='https://raw.githubusercontent.com/alkafeu/stealthcat-server-check/v1.0.0/stealthcat_check.py'
readonly SOURCE_SHA256='70c06a60da3968915e4bdd1ab14a1eb2879e39925e13782d0d511ad79e2af594'

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.10+ is required. Install it using your distribution tools, then retry.' >&2
    exit 2
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    printf '%s\n' 'Python 3.10+ is required.' >&2
    exit 2
fi

verify_source() {
    python3 - "$1" "${SOURCE_SHA256}" <<'PY'
import hashlib
import hmac
from pathlib import Path
import sys

path = Path(sys.argv[1])
if path.stat().st_size > 262144:
    raise SystemExit('Downloaded file is too large; refused execution.')
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if not hmac.compare_digest(actual, sys.argv[2]):
    raise SystemExit('SHA256 mismatch; refused execution.')
PY
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/stealthcat-check-bootstrap.XXXXXXXX")"
child_pid=''
trap 'rm -f -- "${temporary_dir}/stealthcat_check.py"; rmdir -- "${temporary_dir}"' EXIT
stop_child() {
    trap '' INT TERM
    if [[ -n "${child_pid}" ]]; then
        kill -s "$1" "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
    fi
    exit "$2"
}
trap 'stop_child INT 130' INT
trap 'stop_child TERM 143' TERM
chmod 700 "${temporary_dir}"
if [[ -f "${script_dir}/stealthcat_check.py" ]]; then
    python3 - "${script_dir}/stealthcat_check.py" "${temporary_dir}/stealthcat_check.py" <<'PY'
from pathlib import Path
import sys

with Path(sys.argv[1]).open('rb') as source:
    contents = source.read(262145)
if len(contents) > 262144:
    raise SystemExit('Source file is too large; refused execution.')
with Path(sys.argv[2]).open('xb') as destination:
    destination.write(contents)
PY
else
    if ! command -v curl >/dev/null 2>&1; then
        printf '%s\n' 'curl is required for standalone bootstrap. Or download the Python file alongside this launcher.' >&2
        exit 2
    fi
    printf 'Downloading verified StealthCat server check v%s...\n' "${VERSION}" >&2
    curl --disable --fail --silent --show-error --location --max-redirs 3 \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 60 --max-filesize 262144 \
        --output "${temporary_dir}/stealthcat_check.py" "${SOURCE_URL}" &
    child_pid=$!
    wait "${child_pid}"
    child_pid=''
fi
verify_source "${temporary_dir}/stealthcat_check.py"
set +e
python3 "${temporary_dir}/stealthcat_check.py" "$@" &
child_pid=$!
wait "${child_pid}"
status=$?
child_pid=''
set -e
exit "${status}"
