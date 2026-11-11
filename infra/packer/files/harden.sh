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

# AWS Marketplace scans every AMI version over SSH, so sshd stays in the image, key only.
# No key is baked in, the templates launch with no key pair and no inbound rule, so in a
# deployment Session Manager is still the only way in. This file sorts before
# 50-cloud-init.conf, and sshd keeps the first value it reads.
cat > /etc/ssh/sshd_config.d/10-liftproof.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
CONF
chmod 0644 /etc/ssh/sshd_config.d/10-liftproof.conf
passwd -l root

# Patches arrive as a new image version, not in place (decision 138). The instance has no
# route to the Ubuntu archive (egress is the VPC endpoints, S3 and the declared systems),
# so unattended-upgrades and the apt timers could only fail every day, and an image that
# changes itself would no longer be the one the release's Inspector scan passed. Every
# release is built from a fully upgraded base (provision.sh dist-upgrade) and scanned.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
CONF
systemctl disable apt-daily.timer apt-daily-upgrade.timer
systemctl disable unattended-upgrades.service 2>/dev/null || true
date -u +%Y-%m-%d > /etc/mvt/image-built

# Session Manager sessions time out; long runs go under systemd, never in a shell.
cat > /etc/profile.d/liftproof.sh <<'CONF'
echo "Liftproof $(cat /etc/mvt/version), image built $(cat /etc/mvt/image-built); OS patches arrive as new AWS Marketplace versions."
echo "Run long commands with: sudo systemd-run --unit=liftproof-job --collect -p User=mvt liftproof ..."
CONF
