#!/usr/bin/env bash
# The scheduler service (spec 14), which does nothing until a project file has schedules,
# and the web UI (spec 4), bound to 127.0.0.1 and reached through SSM port forwarding.
# Before both, mvt-restore brings the project files back from S3 on a replacement
# instance (spec 3); on a new deployment it finds none and does nothing.
set -euo pipefail

install -m 0644 /tmp/liftproof-files/mvt-scheduler.service /etc/systemd/system/
install -m 0644 /tmp/liftproof-files/mvt-ui.service /etc/systemd/system/
install -m 0644 /tmp/liftproof-files/mvt-restore.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mvt-restore.service mvt-scheduler.service mvt-ui.service
