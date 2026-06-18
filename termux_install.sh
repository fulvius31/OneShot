#!/data/data/com.termux/files/usr/bin/bash
#
# OneShot — Termux installer (root required).
#
# OneShot ships its own pure-Python Wi-Fi scanner (nl80211) and WPS engine
# (--engine native), so this installer does NOT pull in wpa_supplicant or iw.
# The only external binary still used is pixiewps (the offline Pixie-Dust crack).
#
# Run directly:
#   curl -sSf https://raw.githubusercontent.com/fulvius31/OneShot/master/termux_install.sh | bash
#
set -e

echo "[*] Updating package lists…"
pkg update -y

echo "[*] Enabling root-repo (provides pixiewps)…"
pkg install -y root-repo

echo "[*] Installing dependencies (no wpa_supplicant, no iw)…"
pkg install -y git tsu python pixiewps

echo "[*] Fetching OneShot…"
if [ -d OneShot/.git ]; then
    git -C OneShot pull --ff-only || true
else
    git clone --depth 1 https://github.com/fulvius31/OneShot OneShot
fi

cat <<'EOF'

[+] Done.

Run a Pixie-Dust attack using the built-in engine (no wpa_supplicant / iw):

    sudo python OneShot/oneshot.py -i wlan0 --iface-down -K \
         --engine native --scanner nl80211

The native engine is driver-dependent; if it does not work on your adapter,
install wpa_supplicant + iw (pkg install wpa-supplicant iw) and drop the
--engine/--scanner flags to use the classic path.
EOF
