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

First DISABLE Wi-Fi in Android settings (disconnecting is not enough — the system
wpa_supplicant keeps the chip busy). Then run a Pixie-Dust attack:

    sudo python OneShot/oneshot.py -i wlan0 -K

The built-in native engine talks to nl80211 directly. Most internal phone chips
are FullMAC (Broadcom/Qualcomm) and refuse a raw association (you'll see
"association rejected (status 1)"). On those, drive wpa_supplicant instead — it
uses the system binary under /system/bin or /vendor/bin/hw:

    sudo python OneShot/oneshot.py -i wlan0 -b <BSSID> -K --wpa-supplicant

For reliable native-engine support, use an external USB adapter (mac80211).
EOF
