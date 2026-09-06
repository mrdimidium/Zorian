#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nikolay Govorov
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

TESOR_USER=${TESOR_USER:-tesor}
TESOR_GROUP=${TESOR_GROUP:-${TESOR_USER}}

nologin=/usr/sbin/nologin
[ -x "$nologin" ] || nologin=/sbin/nologin
[ -x "$nologin" ] || nologin=/bin/false

if ! getent group "$TESOR_GROUP" >/dev/null; then
  if command -v groupadd >/dev/null; then
    groupadd --system "$TESOR_GROUP"
  else
    addgroup -S "$TESOR_GROUP"
  fi
fi

if ! getent passwd "$TESOR_USER" >/dev/null; then
  if command -v useradd >/dev/null; then
    useradd --system --gid "$TESOR_GROUP" --no-create-home --shell "$nologin" "$TESOR_USER"
  else
    adduser -S -H -G "$TESOR_GROUP" -s "$nologin" "$TESOR_USER"
  fi
fi
