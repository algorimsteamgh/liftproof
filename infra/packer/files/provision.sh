#!/usr/bin/env bash
# Install Liftproof into a single virtual environment, run by systemd. No install step
# for the customer (PRD P1). Base image: Ubuntu 24.04 LTS.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y -o Dpkg::Options::=--force-confold dist-upgrade
apt-get -y install python3.12 python3.12-venv chrony gnupg curl ca-certificates

# Amazon Time Sync Service over the link-local address
cat > /etc/chrony/sources.d/aws.sources <<'CONF'
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4
CONF
systemctl enable chrony

# Session Manager is how the build and the customer get in. Canonical's EC2 images
# ship the agent as a snap; install it if this base did not.
snap list amazon-ssm-agent >/dev/null 2>&1 || snap install amazon-ssm-agent --classic
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service

# CloudWatch agent: not in the Ubuntu archive. The package is checked against the
# AWS signing key, pinned by fingerprint, before it is installed.
CW_KEY_FPR="937616F3450B7D806CBD9725D58167303B789C72"
cw=https://amazoncloudwatch-agent-${AWS_REGION}.s3.${AWS_REGION}.amazonaws.com
work=$(mktemp -d)
curl -fsSL -o "$work/agent.deb" "$cw/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
curl -fsSL -o "$work/agent.deb.sig" "$cw/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb.sig"
curl -fsSL -o "$work/agent.gpg" https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg
export GNUPGHOME="$work/gnupg"
install -d -m 0700 "$GNUPGHOME"
gpg --batch --import "$work/agent.gpg"
gpg --batch --with-colons --fingerprint | awk -F: '$1=="fpr"{print $10}' | grep -qx "$CW_KEY_FPR"
gpg --batch --verify "$work/agent.deb.sig" "$work/agent.deb"
apt-get -y install "$work/agent.deb"
unset GNUPGHOME
rm -rf "$work"
# The agent runs as cwagent; adm is Ubuntu's group for reading logs
id cwagent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cwagent
usermod -aG adm cwagent

useradd --system --home-dir /var/lib/mvt --shell /usr/sbin/nologin mvt
install -d -o root -g root -m 0755 /opt/mvt /etc/mvt
install -d -o mvt -g mvt -m 0750 /var/lib/mvt /var/lib/mvt/projects /var/lib/mvt/cache
# setgid adm: log files the product writes are readable by the CloudWatch agent, which
# still cannot read anything under /var/lib/mvt
install -d -o mvt -g adm -m 2750 /var/log/mvt

python3.12 -m venv /opt/mvt
/opt/mvt/bin/pip install --no-cache-dir --upgrade pip
/opt/mvt/bin/pip install --no-cache-dir /tmp/liftproof-*.whl
ln -sf /opt/mvt/bin/liftproof /usr/local/bin/liftproof
ln -sf /opt/mvt/bin/liftproof /usr/local/bin/mvt

# A worked example that runs with nothing to set up (spec 17): two folders and a
# files-only project, listed in the UI and runnable from the run document.
install -d -o root -g root -m 0755 /opt/mvt/example
cp -r /tmp/liftproof-files/example/source /tmp/liftproof-files/example/target /opt/mvt/example/
chown -R root:root /opt/mvt/example
chmod -R u=rwX,go=rX /opt/mvt/example
install -o mvt -g mvt -m 0640 /tmp/liftproof-files/example/example.yaml /var/lib/mvt/projects/

# Database TLS (spec 15). The Amazon RDS CA bundle is kept in the repository, so each
# release ships a reviewed copy (refresh it from
# https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem). Liftproof uses
# the system CAs plus that bundle whenever a project names no sslrootcert; the hook
# keeps the combined file current when the ca-certificates package is updated.
install -d -o root -g root -m 0755 /opt/mvt/certs
install -m 0644 /tmp/liftproof-files/rds-global-bundle.pem /opt/mvt/certs/
install -d /etc/ca-certificates/update.d
cat > /etc/ca-certificates/update.d/liftproof <<'HOOK'
#!/bin/sh
set -e
cat /etc/ssl/certs/ca-certificates.crt /opt/mvt/certs/rds-global-bundle.pem \
  > /opt/mvt/certs/ca-bundle.pem.new
chmod 0644 /opt/mvt/certs/ca-bundle.pem.new
mv /opt/mvt/certs/ca-bundle.pem.new /opt/mvt/certs/ca-bundle.pem
HOOK
chmod 0755 /etc/ca-certificates/update.d/liftproof
/etc/ca-certificates/update.d/liftproof

# Chromium for record and replay, in a shared read-only location. Playwright's own
# installer pulls the system libraries Chromium needs from the Ubuntu archive.
browsers=/opt/mvt/browsers
if /opt/mvt/bin/python -c "import playwright" 2>/dev/null; then
  PLAYWRIGHT_BROWSERS_PATH=$browsers /opt/mvt/bin/python -m playwright install --with-deps chromium
  chmod -R a+rX "$browsers"
  # every unit (including systemd-run jobs) and every login shell finds it
  install -d /etc/systemd/system.conf.d
  printf '[Manager]\nDefaultEnvironment=PLAYWRIGHT_BROWSERS_PATH=%s\n' "$browsers" \
    > /etc/systemd/system.conf.d/90-liftproof.conf
  echo "PLAYWRIGHT_BROWSERS_PATH=$browsers" >> /etc/environment
fi

# ATS-009: audit what the image installed, not only what the release runner resolved.
# A known vulnerability in the image's own environment fails the build. Chromium is
# Playwright's build, which no scanner covers, so its version is recorded with the
# release evidence instead.
evidence=/var/tmp/ami-dependency-audit.txt
python3.12 -m venv /var/tmp/audit
/var/tmp/audit/bin/pip install --no-cache-dir --quiet pip-audit
/opt/mvt/bin/pip freeze --all --exclude liftproof > /var/tmp/ami-requirements.txt
{
  echo "# packages installed in /opt/mvt"
  cat /var/tmp/ami-requirements.txt
  echo "# Playwright browsers in /opt/mvt/browsers"
  ls /opt/mvt/browsers 2>/dev/null || echo "none"
  echo "# pip-audit"
} > "$evidence"
/var/tmp/audit/bin/pip-audit --strict --progress-spinner off --no-deps --disable-pip \
  -r /var/tmp/ami-requirements.txt 2>&1 | tee -a "$evidence"
rm -rf /var/tmp/audit /var/tmp/ami-requirements.txt

# Record exact versions, including the AWS SDK, on the image (AWSAPI-004)
/opt/mvt/bin/liftproof version --format json > /etc/mvt/build-info.json
echo "${LIFTPROOF_VERSION}" > /etc/mvt/version

install -m 0644 /tmp/liftproof-files/mvt-cwagent.service /etc/systemd/system/
install -m 0755 /tmp/liftproof-files/mvt-cwagent-config /usr/local/sbin/
systemctl enable mvt-cwagent.service
