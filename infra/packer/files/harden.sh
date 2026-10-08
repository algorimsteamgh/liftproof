#!/usr/bin/env bash
# Host hardening. Core dumps are off because a dump can capture secrets held in
# memory during a run (Technical Spec 15). Base image: Ubuntu 24.04 LTS.
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
# Ubuntu's crash reporter collects core dumps on its own; turn it off too.
systemctl disable --now apport.service 2>/dev/null || true
sed -i 's/^enabled=1/enabled=0/' /etc/default/apport 2>/dev/null || true
cat > /etc/sysctl.d/90-liftproof.conf <<'CONF'
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
CONF

# Session Manager is the only way in: no SSH daemon in the shipped image.
# Ubuntu 24.04 starts sshd from a socket unit, so both are disabled and masked.
systemctl disable ssh.socket ssh.service 2>/dev/null || true
systemctl mask ssh.socket ssh.service

# Session Manager sessions time out; long runs go under systemd, never in a shell.
cat > /etc/profile.d/liftproof.sh <<'CONF'
echo "Liftproof $(cat /etc/mvt/version). Run long commands with: sudo systemd-run --unit=liftproof-job --collect -p User=mvt liftproof ..."
CONF
