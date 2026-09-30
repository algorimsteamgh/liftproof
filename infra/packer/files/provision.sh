#!/usr/bin/env bash
# Install Certus into a single virtual environment, run by systemd. No install step
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
/opt/mvt/bin/pip install --no-cache-dir /tmp/certus-*.whl
ln -sf /opt/mvt/bin/certus /usr/local/bin/certus
ln -sf /opt/mvt/bin/certus /usr/local/bin/mvt

# Record exact versions, including the AWS SDK, on the image (AWSAPI-004)
/opt/mvt/bin/certus version --format json > /etc/mvt/build-info.json
echo "${CERTUS_VERSION}" > /etc/mvt/version

install -m 0644 /tmp/certus-files/mvt-cwagent.service /etc/systemd/system/
install -m 0755 /tmp/certus-files/mvt-cwagent-config /usr/local/sbin/
systemctl enable mvt-cwagent.service
