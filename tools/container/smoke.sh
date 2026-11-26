#!/bin/sh
# Level-2 container smoke (blueprint 7.1) for the nightly tier-2 jobs and for local runs:
#     podman run --rm -v "$PWD/dist":/dist:ro <image> sh /dist/smoke.sh
# (the workflow copies this file next to motp.pyz). Installs python3 where the image lacks
# it, then runs the archive under `python3 -I -S`: version, the demo at 80 and 50 columns,
# show, modules, doctor and one collector run as root without the sandbox. Asserts: exit
# code 0 where one is promised, no traceback anywhere, no escape byte with NO_COLOR, no
# line wider than the requested width. Prints "SMOKE-OK" at the end, "SMOKE-FAIL <why>"
# and exit 1 on the first failure. Finishes in seconds once Python is installed.
set -u
PYZ=/dist/motp.pyz
fail() { echo "SMOKE-FAIL $1"; exit 1; }

if ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3 >/dev/null
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive --quiet install python3 >/dev/null
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm --quiet python >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache -q python3 >/dev/null
    fi
fi
command -v python3 >/dev/null 2>&1 || fail "no python3"
python3 -c 'import sys; print("python", sys.version.split()[0])'
[ -f "$PYZ" ] || fail "no $PYZ"

run() { python3 -I -S "$PYZ" "$@" 2>&1; }

out=$(run version) || fail "version exit $?"
case "$out" in "motp "*) echo "$out" ;; *) fail "version printed: $out" ;; esac

for width in 80 50; do
    out=$(NO_COLOR=1 run preview --demo --width "$width") || fail "preview $width exit $?"
    printf '%s\n' "$out" | grep -q "$(printf '\033')" && fail "escape byte in preview $width"
    long=$(printf '%s\n' "$out" | python3 -I -c "
import sys
print(max((len(l) for l in sys.stdin.read().splitlines()), default=0))")
    [ "$long" -le "$width" ] || fail "preview $width has a line of $long"
done

for cmd in show modules doctor "collect --no-sandbox"; do
    # shellcheck disable=SC2086 # the command words are split on purpose
    out=$(NO_COLOR=1 run $cmd)
    printf '%s\n' "$out" | grep -q 'Traceback' && fail "traceback from $cmd"
    printf '%s\n' "$out" | grep -q "$(printf '\033')" && fail "escape byte from $cmd"
    echo "ran: motp $cmd"
done
echo "SMOKE-OK"
