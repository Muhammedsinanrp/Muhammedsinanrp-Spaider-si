#!/usr/bin/env bash
# =============================================================================
#  SPAIDER Linux Tool Uninstaller
# =============================================================================

set -e

SUDO=""
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

echo "[*] Removing SPAIDER binary symlink..."
$SUDO rm -f /usr/local/bin/spaider

if [ -f "/etc/systemd/system/spaider.service" ]; then
    echo "[*] Stopping and disabling systemd service..."
    $SUDO systemctl stop spaider 2>/dev/null || true
    $SUDO systemctl disable spaider 2>/dev/null || true
    $SUDO rm -f /etc/systemd/system/spaider.service
    $SUDO systemctl daemon-reload 2>/dev/null || true
fi

echo "[✔] SPAIDER Linux CLI tool successfully uninstalled."
