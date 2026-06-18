[![tests](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml/badge.svg)](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml)

# Overview
**OneShot** performs the [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) and online WPS PIN attacks **without monitor mode** — and is now **fully self-contained pure Python**: no `wpa_supplicant`, no `iw`, no `pixiewps`, no `pip` packages. Just Python 3.6+ and root.

# Features
 - **Pixie Dust attack** with a built-in pure-Python cracker (Ralink/MediaTek LFSR inversion + trivial nonce cases);
 - **online WPS PIN bruteforce** (half-by-half);
 - full WPS **PIN → PSK** recovery;
 - a broad set of offline WPS PIN algorithms: 24/28/32/36/40/44/48-bit, D-Link(+1), ASUS, Airocon, EasyBox, Arris, TrendNet, FTE, plus serial-based Belkin and Orange (see `--serial`);
 - built-in **nl80211 (netlink) Wi-Fi scanner** with vulnerability highlighting;
 - built-in **WPS engine** — associates via nl80211 (managed mode, no monitor mode) and runs the EAP-WSC exchange itself over a raw EAPOL socket.

Everything talks to the kernel directly (nl80211 + `AF_PACKET`), so no external Wi-Fi tooling is needed.

# Requirements
 - Python 3.6 and above — **standard library only**;
 - **root** (the scanner, association and EAPOL need `CAP_NET_ADMIN`/`CAP_NET_RAW`).

> ⚠️ **Experimental.** The crypto and WPS protocol layers are unit-tested, but the live nl80211-association + EAPOL transport is driver-dependent and should be validated on your hardware. It needs a free interface — stop NetworkManager / the system `wpa_supplicant` first (or use `--iface-down`).

# Setup
OneShot is two files — `oneshot.py` plus its helper modules (`nl80211_scan.py`, `wps_connect.py`, `wps_crypto.py`, `pixie.py`) — so clone the repo rather than fetching a single script.

## Debian/Ubuntu/Arch
 ```
 sudo apt install -y python3 git        # Debian/Ubuntu
 sudo pacman -S python git              # Arch
 git clone --depth 1 https://github.com/fulvius31/OneShot
 ```

## [Termux](https://termux.com/) (rooted Android)
#### Using installer
 ```
 curl -sSf https://raw.githubusercontent.com/fulvius31/OneShot/master/termux_install.sh | bash
 ```
#### Manually
 ```
 pkg install -y git tsu python
 git clone --depth 1 https://github.com/fulvius31/OneShot
 ```

# Usage
```
 oneshot.py <arguments>
 Required arguments:
     -i, --interface=<wlan0>  : Name of the interface to use

 Optional arguments:
     -b, --bssid=<mac>        : BSSID of the target AP
     -s, --ssid=<ssid>        : SSID of the target AP
     -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
     -K, --pixie-dust         : Run Pixie Dust attack
     -B, --bruteforce         : Run online bruteforce attack
     --serial=<serial>        : Device serial number — enables the Belkin and Orange PIN algorithms

 Advanced arguments:
     -d, --delay=<n>          : Set the delay between pin attempts
     -w, --write              : Write AP credentials to the file on success
     --iface-down             : Down network interface when the work is finished
     -l, --loop               : Run in a loop
     -r, --reverse-scan       : Reverse order of networks in the list. Useful on small displays
     --vuln-list=<filename>   : Use custom file with vulnerable devices list ['vulnwsc.txt']
     --mtk-wifi               : Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit
                                (for internal Wi-Fi adapters implemented in MediaTek SoCs). Turn off Wi-Fi in the system settings before using this.
     -v, --verbose            : Verbose output
 ```

## Usage examples
Pixie Dust attack on a specified BSSID:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K
 ```
Scan, pick a network, then Pixie Dust:
 ```
 sudo python3 oneshot.py -i wlan0 -K
 ```
Online WPS bruteforce:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B
 ```
Try a specific PIN and recover the PSK:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -p 12345670
 ```

## Where results are stored
OneShot keeps its data under `~/.OneShot/` (of the user it runs as — i.e. `root` when run with `sudo`):
 - `~/.OneShot/reports/` — recovered credentials (`stored.txt`, `stored.csv`), written with `-w`/`--write`;
 - `~/.OneShot/sessions/` — resumable online-bruteforce sessions;
 - `~/.OneShot/pixiewps/` — recovered PINs.

## Development
Standard library only. Run the test suite (no Wi-Fi hardware or root required):
 ```
 python3 -m unittest discover -s tests
 ```
The tests cover the PIN-generation algorithms, the WPS crypto (DH/KDF/AES vs FIPS-197), the EAP-WSC message layer (validated against a mirror enrollee through M7), the nl80211 attribute/IE/WPS decoders, and the Pixie-Dust cracker. They run on every push via [GitHub Actions](.github/workflows/tests.yml).

## Troubleshooting
#### "RTNETLINK answers: Operation not possible due to RF-kill"
 Just run: ```sudo rfkill unblock wifi```
#### "Device or resource busy (-16)" / association fails
 Another supplicant owns the interface. Disable Wi-Fi in the system settings and kill NetworkManager / `wpa_supplicant`, or run with ```--iface-down```.
#### The wlan0 interface disappears when Wi-Fi is disabled on Android devices with MediaTek SoC
 Run with the `--mtk-wifi` flag to initialize the Wi-Fi device driver.

# Acknowledgements
## Special Thanks
* `rofl0r` for the initial implementation;
* `Monohrom` for testing, help in catching bugs, some ideas;
* `Wiire` for `pixiewps` and `drygdryg` for the `rofl0r` repo work — the references this pure-Python reimplementation follows.
