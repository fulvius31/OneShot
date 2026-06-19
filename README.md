[![tests](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml/badge.svg)](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml)

# Overview
**OneShot** performs the [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) and online WPS PIN attacks **without monitor mode**. Its default engine is **self-contained pure Python** — its own nl80211 scanner, WPS engine and Pixie-Dust cracker, no `iw`/`pixiewps`/`pip` packages. For internal **FullMAC** chips that refuse a raw nl80211 association (notably Broadcom on Android), it can instead **drive a real `wpa_supplicant`** — see [Engines](#engines).

# Features
 - **Pixie Dust attack** with a built-in pure-Python cracker (Ralink/MediaTek LFSR inversion + trivial nonce cases);
 - **online WPS PIN bruteforce** (half-by-half);
 - full WPS **PIN → PSK** recovery;
 - a broad set of offline WPS PIN algorithms: 24/28/32/36/40/44/48-bit, D-Link(+1), ASUS, Airocon, EasyBox, Arris, TrendNet, FTE, plus serial-based Belkin and Orange (see `--serial`);
 - built-in **nl80211 (netlink) Wi-Fi scanner** with vulnerability highlighting;
 - built-in **WPS engine** — associates via nl80211 (managed mode, no monitor mode) and runs the EAP-WSC exchange itself over a raw EAPOL socket.

# Engines
OneShot has two WPS backends; the offline scanner and Pixie-Dust cracker are shared (always pure Python):

| Engine | Flag | Use it for |
| --- | --- | --- |
| **Native** (default) | *(none)* | softMAC (`mac80211`) drivers and external USB adapters. Talks to the kernel directly over nl80211 + `AF_PACKET`; no external Wi-Fi tooling. |
| **wpa_supplicant** | `--wpa-supplicant` | Internal **FullMAC** chips (e.g. Broadcom `dhd` on Android) where a raw nl80211 `CONNECT` from a third-party process is refused (association `status 1`). Drives a real `wpa_supplicant` (needs the binary, built with `CONFIG_WPS=y`) and feeds its `-K -d` output to the same built-in Pixie-Dust cracker. Currently supports `-K` (Pixie-Dust) and `-p` (single PIN → PSK). |

If the native engine reports `association rejected (status 1)` on an internal Android chip, switch to `--wpa-supplicant`.

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

> **Android internal Wi-Fi chips.** First **disable Wi-Fi in Android settings** — *disconnecting is not enough*; the system `wpa_supplicant` keeps the chip busy and a raw association is refused (`status 1`). OneShot brings the interface up itself. Most internal phone chips are **FullMAC** (Broadcom/Qualcomm) and reject the native engine's raw nl80211 `CONNECT`; on those, add **`--wpa-supplicant`** (it needs a `wpa_supplicant` binary with `CONFIG_WPS=y` — the system one under `/system/bin` or `/vendor/bin/hw` is auto-detected, or pass `--wpa-supplicant-path`). For reliable native-engine support, an **external USB adapter** (`mac80211`: rtl8812au / mt76 / ath9k_htc) is the best option.

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
     --wpa-supplicant         : Drive a real wpa_supplicant instead of the native engine
                                (for internal FullMAC chips, e.g. Broadcom on Android). Disable system Wi-Fi first.
     --wpa-supplicant-path=<p>: Path to the wpa_supplicant binary (default: search PATH and Android locations)
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
Pixie Dust on an internal FullMAC chip (Android), driving wpa_supplicant (disable system Wi-Fi first):
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K --wpa-supplicant
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
