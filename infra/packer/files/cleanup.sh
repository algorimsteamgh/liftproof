#!/usr/bin/env bash
# Leave nothing build specific or secret in the image (Marketplace AMI requirements).
set -euo pipefail
rm -f /tmp/liftproof-*.whl
rm -rf /tmp/liftproof-files
dnf clean all
rm -rf /var/cache/dnf
find /home /root -name authorized_keys -delete
rm -f /etc/ssh/ssh_host_*
truncate -s 0 /var/log/*.log || true
rm -rf /var/lib/cloud/instances/*
cloud-init clean --logs || true
history -c || true
