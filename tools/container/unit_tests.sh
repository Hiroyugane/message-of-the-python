#!/bin/sh
# Runs inside the container started by tools/container_test.py. The repository is mounted
# read-only at /src. Arguments are passed to pytest. Stage lines ("MOTP-STAGE <name>") let
# the caller show progress.
set -eu

stage() { echo "MOTP-STAGE $1"; }

stage python
if ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3 >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache -q python3 >/dev/null
    else
        echo "no known package manager to install python3" >&2
        exit 1
    fi
fi
python3 -c 'import sys, unicodedata; print("python", sys.version.split()[0], "unicode", unicodedata.unidata_version)'

stage copy
# The mount has no usable owners or modes: work on the container's own filesystem.
python3 -I -c '
import shutil
shutil.copytree(
    "/src", "/work",
    ignore=shutil.ignore_patterns(
        ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
        "dist", "*.mo", "*.pyc",
    ),
)
'

stage accounts
# Test accounts, the two probe users and an admin group (tools/container/accounts.sh).
. /src/tools/container/accounts.sh

stage venv
if ! python3 -m venv /venv >/dev/null 2>&1; then
    # Debian-family images ship venv without ensurepip unless python3-venv is installed.
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >/dev/null
    fi
    python3 -m venv /venv
fi
/venv/bin/python -m pip install -q --disable-pip-version-check "pytest>=8.4,<10"
/venv/bin/python -m pytest --version

stage test
cd /work
# Tests marked needs_linux_owner must run here, never be skipped.
export MOTP_REQUIRE_ROOT_TESTS=1
exec /venv/bin/python -m pytest -q -p no:cacheprovider "$@"
