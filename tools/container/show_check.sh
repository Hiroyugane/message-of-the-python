#!/bin/sh
# Runs inside the container started by tools/container_test.py --script (phase 5). The
# repository is mounted read-only at /src. Builds dist/motp.pyz from a copy, then
# tools/measure_show.py unpacks it, compiles bytecode with this container's Python (D31),
# checks the output of `motp show` and prints the median time of 20 runs. Arguments go to
# measure_show.py. Stage lines ("MOTP-STAGE <name>") let the caller show progress.
set -eu

stage() { echo "MOTP-STAGE $1"; }

stage python
if ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3 >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache -q python3 >/dev/null
    else
        echo "no known package manager to install python3" >&2
        exit 1
    fi
fi
python3 -c 'import sys; print("python", sys.version.split()[0])'

stage copy
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
# The probe users, so tools/measure_show.py --collect can run the collector first.
. /src/tools/container/accounts.sh

stage build
cd /work
python3 -I tools/build_pyz.py --output /work/dist/motp.pyz

stage measure
exec python3 -I tools/measure_show.py --pyz /work/dist/motp.pyz "$@"
