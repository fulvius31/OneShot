#!/data/data/com.termux/files/usr/bin/bash
#
# OneShot — Termux installer (root required).
#
# OneShot is fully self-contained pure Python: it ships its own nl80211 scanner,
# WPS engine and Pixie-Dust cracker, so this installer pulls in NO external
# Wi-Fi tooling (no wpa_supplicant, no iw, no pixiewps) — only Python + a root
# shell helper.
#
# Run directly:
#   curl -sSf https://raw.githubusercontent.com/fulvius31/OneShot/master/termux_install.sh | bash
#
set -e

echo "[*] Updating package lists…"
pkg update -y

echo "[*] Installing dependencies (Python + root shell only)…"
pkg install -y git tsu python

echo "[*] Fetching OneShot…"
if [ -d OneShot/.git ]; then
    git -C OneShot pull --ff-only || true
else
    git clone --depth 1 https://github.com/fulvius31/OneShot OneShot
fi

cat <<'EOF'

[+] Done.

Run a Pixie-Dust attack (everything is built in — no external binaries):

    sudo python OneShot/oneshot.py -i wlan0 --iface-down -K

The built-in WPS engine is driver-dependent. If association fails, make sure no
other supplicant owns wlan0 (stop the system Wi-Fi / NetworkManager first).
EOF
