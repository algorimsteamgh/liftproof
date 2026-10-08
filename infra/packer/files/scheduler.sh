#!/usr/bin/env bash
# The scheduler service (spec 14). It does nothing until a project file has schedules.
set -euo pipefail

install -m 0644 /tmp/liftproof-files/mvt-scheduler.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mvt-scheduler.service
