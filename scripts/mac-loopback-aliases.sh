#!/usr/bin/env bash
# Hiten | 2026
# mac-loopback-aliases.sh
#
# macOS only answers on 127.0.0.1 by default. labtest gives every
# scenario its own source address so their results cannot mix, so on
# a Mac it needs extra loopback addresses. This adds (or removes)
# 127.0.0.10 upwards on lo0. The aliases last until reboot.
#
#   sudo ./scripts/mac-loopback-aliases.sh add            # 127.0.0.10-127.0.0.99
#   sudo ./scripts/mac-loopback-aliases.sh add --count 40
#   sudo ./scripts/mac-loopback-aliases.sh remove
#   ./scripts/mac-loopback-aliases.sh status
#
# Then run labtest as usual; it picks addresses from 127.0.0.10-127.0.0.99.

set -euo pipefail

ACTION="${1:-status}"
COUNT=90
if [ "${2:-}" = "--count" ]; then COUNT="${3:?--count needs a number}"; fi
FIRST=10
LAST=$((FIRST + COUNT - 1))
if [ "$LAST" -gt 254 ]; then echo "count too large (max 245)" >&2; exit 1; fi

if [ "$(uname)" != "Darwin" ]; then
  echo "Not macOS. Linux already answers on all of 127.0.0.0/8; nothing to do."
  exit 0
fi

case "$ACTION" in
  add)
    [ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
    for i in $(seq "$FIRST" "$LAST"); do ifconfig lo0 alias "127.0.0.$i" up; done
    echo "Added 127.0.0.$FIRST to 127.0.0.$LAST on lo0 (until reboot)."
    ;;
  remove)
    [ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
    for i in $(seq "$FIRST" 254); do ifconfig lo0 -alias "127.0.0.$i" 2>/dev/null || true; done
    echo "Removed aliases from 127.0.0.$FIRST upwards."
    ;;
  status)
    n=$(ifconfig lo0 | grep -c 'inet 127\.0\.0\.\([1-9][0-9]\|[12][0-9][0-9]\) ' || true)
    echo "$n extra loopback aliases on lo0."
    ;;
  *) echo "usage: $0 add [--count N] | remove | status" >&2; exit 1 ;;
esac
