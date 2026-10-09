#!/usr/bin/env bash
# The scheduler service (spec 14), which does nothing until a project file has schedules,
# and the web UI (spec 4), bound to 127.0.0.1 and reached through SSM port forwarding.
set -euo pipefail

install -m 0644 /tmp/liftproof-files/mvt-scheduler.service /etc/systemd/system/
install -m 0644 /tmp/liftproof-files/mvt-ui.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mvt-scheduler.service mvt-ui.service
