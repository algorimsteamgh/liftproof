#!/usr/bin/env bash
# Host hardening. Core dumps are off because a dump can capture secrets held in
# memory during a run (Technical Spec 15).
set -euo pipefail

cat > /etc/security/limits.d/90-no-core.conf <<'CONF'
* hard core 0
CONF
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf <<'CONF'
[Coredump]
Storage=none
ProcessSizeMax=0
CONF
cat > /etc/sysctl.d/90-certus.conf <<'CONF'
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
CONF

# Session Manager is the only way in: no SSH daemon in the shipped image.
systemctl disable sshd || true

# Session Manager sessions time out; long runs go under systemd, never in a shell.
cat > /etc/profile.d/certus.sh <<'CONF'
echo "Certus $(cat /etc/mvt/version). Run long commands with: sudo systemd-run --unit=certus-job --collect -p User=mvt certus ..."
CONF
