#!/bin/sh
# Runs once while the login test image is built (tools/container/login/Containerfile).
# Adds sshd, the ssh client, rsync, zsh, fish and script(1). Host keys are removed here
# and generated when a test container starts; no key ever leaves the container.
set -eu
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends openssh-server openssh-client rsync \
        zsh fish bsdutils coreutils >/dev/null
    # Ubuntu's /etc/profile.d/01-locale-fix.sh (base-files) resets a LANG whose locale is
    # not installed to C.UTF-8, as the RHEL family's lang.sh does: generate the German one.
    if [ -f /etc/profile.d/01-locale-fix.sh ]; then
        apt-get install -y -qq --no-install-recommends locales >/dev/null
        sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
        locale-gen >/dev/null
    fi
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    sshd_unit=ssh.service
elif command -v dnf >/dev/null 2>&1; then
    if grep -q 'ID="almalinux"' /etc/os-release; then
        dnf install -y -q epel-release >/dev/null  # fish is in EPEL on the RHEL family
    fi
    dnf install -y -q openssh-server openssh-clients rsync zsh fish util-linux >/dev/null
    # The German locale for the language check: this family's /etc/profile.d/lang.sh
    # resets a LANG whose locale is not installed to C.UTF-8 before any later hook runs.
    dnf install -y -q glibc-langpack-de >/dev/null
    dnf install -y -q util-linux-script >/dev/null 2>&1 || true  # script(1) on Fedora
    dnf clean all >/dev/null
    sshd_unit=sshd.service
else
    echo "no known package manager" >&2
    exit 1
fi
rm -f /etc/ssh/ssh_host_*
# The language check sends the client's LANG. Debian's sshd accepts it by default; the
# AlmaLinux 9 and Fedora images' sshd configuration does not, so say so there.
if ! grep -rqs '^[[:space:]]*AcceptEnv.*LANG' /etc/ssh/sshd_config /etc/ssh/sshd_config.d; then
    mkdir -p /etc/ssh/sshd_config.d
    echo 'AcceptEnv LANG LC_*' > /etc/ssh/sshd_config.d/60-motp-test-locale.conf
fi
# pam_loginuid needs the audit capability, which a container does not have.
for f in /etc/pam.d/sshd /etc/pam.d/login; do
    [ -f "$f" ] && sed -i 's/^\(session[[:space:]]*\)required\([[:space:]]*pam_loginuid\.so\)/\1optional\2/' "$f"
done
# The RHEL family keeps /etc/shadow at mode 0000 and lets root read it by capability. On
# the CI runners every login into AlmaLinux 9 and 10 ended with "Access denied ... by PAM
# account configuration", on AlmaLinux 9 next to "unix_chkpwd: could not obtain user info":
# pam_unix has its helper read the file for the account check. The runners (Ubuntu 24.04)
# have an AppArmor profile for unix_chkpwd that applies inside a container too, by the
# program's path, and grants no capability to pass the mode. That link is inferred (WSL has
# no AppArmor to try it with). With the owner's read bit root needs no capability.
if [ "$(stat -c %a /etc/shadow)" = 0 ]; then
    chmod 0400 /etc/shadow
fi
systemctl enable "$sshd_unit" >/dev/null 2>&1 || true
command -v script zsh fish rsync sshd ssh >/dev/null || ls -l /usr/sbin/sshd
fish --version
zsh --version
