#!/usr/bin/env bash
# Install Liftproof into a single virtual environment, run by systemd. No install step
# for the customer (PRD P1).
set -euo pipefail

dnf -y upgrade --releasever=latest
dnf -y install python3.12 python3.12-pip amazon-cloudwatch-agent amazon-ssm-agent chrony
systemctl enable amazon-ssm-agent chronyd

useradd --system --home-dir /var/lib/mvt --shell /sbin/nologin mvt
install -d -o root -g root -m 0755 /opt/mvt /etc/mvt
install -d -o mvt -g mvt -m 0750 /var/lib/mvt /var/lib/mvt/projects /var/lib/mvt/cache /var/log/mvt

python3.12 -m venv /opt/mvt
/opt/mvt/bin/pip install --no-cache-dir --upgrade pip
/opt/mvt/bin/pip install --no-cache-dir /tmp/liftproof-*.whl
ln -sf /opt/mvt/bin/liftproof /usr/local/bin/liftproof
ln -sf /opt/mvt/bin/liftproof /usr/local/bin/mvt

# Record exact versions, including the AWS SDK, on the image (AWSAPI-004)
/opt/mvt/bin/liftproof version --format json > /etc/mvt/build-info.json
echo "${LIFTPROOF_VERSION}" > /etc/mvt/version

install -m 0644 /tmp/liftproof-files/mvt-cwagent.service /etc/systemd/system/
install -m 0755 /tmp/liftproof-files/mvt-cwagent-config /usr/local/sbin/
systemctl enable mvt-cwagent.service
