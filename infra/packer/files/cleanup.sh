#!/usr/bin/env bash
# Leave nothing build specific or secret in the image (Marketplace AMI requirements).
set -euo pipefail
rm -f /tmp/liftproof-*.whl
rm -rf /tmp/liftproof-files /var/tmp/ami-dependency-audit.txt
apt-get -y autoremove --purge
apt-get clean
rm -rf /var/lib/apt/lists/*
find /home /root -name authorized_keys -delete
rm -f /etc/ssh/ssh_host_*
truncate -s 0 /var/log/*.log || true
rm -rf /var/lib/cloud/instances/*
cloud-init clean --logs || true
# each instance gets its own machine id on first boot
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
history -c || true
