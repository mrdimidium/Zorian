#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nikolay Govorov
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

if [ -x "/bin/systemctl" ] && [ -d /run/systemd/system ] && [ -f /usr/lib/systemd/system/tesor.service ]; then
  /bin/systemctl daemon-reload
  /bin/systemctl enable tesor
fi

if command -v rc-update >/dev/null && [ -f /etc/init.d/tesor ]; then
  rc-update add tesor default
fi
