#!/usr/bin/env bash
# Leave nothing build specific or secret in the image (Marketplace AMI requirements).
set -euo pipefail
rm -f /tmp/liftproof-*.whl
rm -rf /tmp/liftproof-files /var/tmp/ami-dependency-audit.txt
export DEBIAN_FRONTEND=noninteractive
# provision.sh's dist-upgrade installs a newer kernel, but the builder keeps running the
# base image's, which autoremove never removes. Left in the image, its packages carry the
# CVEs the new kernel fixed and fail the Inspector gate. Purge every kernel package not
# of the newest installed version (with DEBIAN_FRONTEND=noninteractive, removing the
# running kernel does not prompt; the image boots the newest).
newest=$( { dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null || true; } \
  | awk '$1 == "ii" {print $2}' | sed -e 's/^linux-image-//' -e 's/-[a-z]*$//' | sort -V | tail -n 1 || true)
if [ -n "$newest" ]; then
  old=$( { dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-*' 2>/dev/null || true; } \
    | awk '$1 == "ii" {print $2}' | grep -E -- '-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+' \
    | grep -vF -- "$newest" || true)
  if [ -n "$old" ]; then
    echo "removing old kernel packages: $old"
    # shellcheck disable=SC2086 # one package name per word
    apt-get -y purge $old
  fi
fi
# python3.12-venv was needed only to create /opt/mvt and the build's audit venv. Its
# python3-pip-whl and python3-setuptools-whl carry pip and urllib3 copies that Inspector
# flags (v0.1.0rc3: CVE-2025-66418, CVE-2025-66471), and nothing on the instance creates a
# venv. /opt/mvt keeps its own upgraded pip, which the in-image pip-audit checked.
# python3.12 runs /opt/mvt: keep it manual so the autoremove below never takes it
apt-mark manual python3.12
apt-get -y purge python3.12-venv python3-pip-whl python3-setuptools-whl
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
