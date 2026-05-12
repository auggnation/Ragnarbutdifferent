#!/bin/bash
# Ragnar on-screen kiosk uninstaller.
# Removes the systemd unit, wrapper, and tty1 autologin drop-in.
# Leaves apt packages (chromium, xorg, etc.) in place — they may be
# wanted independently. Pass --purge to also remove those packages.

set -euo pipefail

SERVICE_FILE="/etc/systemd/system/ragnar-kiosk.service"
WRAPPER_DST="/usr/local/bin/ragnar-kiosk-run"
AUTOLOGIN_DROPIN="/etc/systemd/system/getty@tty1.service.d/autologin.conf"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
    esac
done

if systemctl list-unit-files 2>/dev/null | grep -q '^ragnar-kiosk\.service'; then
    systemctl disable --now ragnar-kiosk.service || true
fi
rm -f "$SERVICE_FILE"
rm -f "$WRAPPER_DST"
rm -f "$AUTOLOGIN_DROPIN"

# Only remove the drop-in directory if it's now empty
if [[ -d "$(dirname "$AUTOLOGIN_DROPIN")" ]]; then
    rmdir --ignore-fail-on-non-empty "$(dirname "$AUTOLOGIN_DROPIN")" || true
fi

systemctl daemon-reload || true

if [[ "$PURGE" -eq 1 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
        chromium-browser xserver-xorg xinit x11-xserver-utils openbox unclutter || true
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true
fi

echo "[kiosk-uninstall] done"
