#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nikolay Govorov
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

if [ -x "/bin/systemctl" ] && [ -d /run/systemd/system ] && [ -f /usr/lib/systemd/system/tesor.service ]; then
  /bin/systemctl stop tesor.service || true
  /bin/systemctl disable tesor.service || true
fi

if command -v rc-service >/dev/null && [ -f /etc/init.d/tesor ]; then
  rc-service tesor stop || true
  rc-update del tesor || true
fi
