#!/bin/sh
# Runs once while the systemd test image is built (tools/container/systemd/Containerfile).
# Installs systemd, Python, sudo (so the installer finds an admin group, D33), the
# account tools and strace (the network check of the package modules), and masks units that
# cannot work in a container.
set -eu
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus python3 sudo passwd procps strace >/dev/null
    apt-get clean
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q systemd dbus python3 sudo shadow-utils procps-ng strace >/dev/null
    dnf clean all >/dev/null
else
    echo "no known package manager" >&2
    exit 1
fi
# Units that need hardware, a console or a writable kernel interface.
for unit in systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket \
    getty.target console-getty.service systemd-firstboot.service systemd-resolved.service \
    systemd-networkd.service systemd-timesyncd.service systemd-homed.service \
    systemd-userdbd.service systemd-userdbd.socket; do
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
python3 -c 'import sys; print("python", sys.version.split()[0])'
systemctl --version | head -1
