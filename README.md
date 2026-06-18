[![tests](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml/badge.svg)](https://github.com/fulvius31/OneShot/actions/workflows/tests.yml)

# Overview
**OneShot** performs [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) without having to switch to monitor mode.
# Features
 - [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack);
 - integrated [3WiFi offline WPS PIN generator](https://3wifi.stascorp.com/wpspin);
 - [online WPS bruteforce](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf);
 - a broad set of offline WPS PIN algorithms: 24/28/32/36/40/44/48-bit, D-Link(+1), ASUS, Airocon, EasyBox, Arris, TrendNet, FTE, plus serial-based Belkin and Orange (see `--serial`);
 - built-in **pure-Python nl80211 (netlink) Wi-Fi scanner** — talks to the kernel directly, so the `iw` binary is no longer required (handy on Android/Termux), with automatic fallback to `iw`;
 - optional built-in **pure-Python WPS engine** (`--engine native`) — associates via nl80211 and runs the EAP-WSC exchange itself (no `wpa_supplicant`, no monitor mode); supports Pixie-Dust and full PIN→PSK recovery;
 - Wi-Fi scanner with vulnerability highlighting.
# Requirements
 - Python 3.6 and above (standard library only — no `pip` packages needed);
 - [Wpa supplicant](https://www.w1.fi/wpa_supplicant/);
 - [Pixiewps](https://github.com/wiire-a/pixiewps);
 - [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw) — **optional**, only used as a fallback scanner (`--scanner iw`); the default built-in nl80211 scanner needs no external binary.

> **Note:** the built-in nl80211 scanner lives in `nl80211_scan.py`. Use `git clone` (below) to get it alongside `oneshot.py`; a single-file `wget` of `oneshot.py` still works but will only scan via `iw`.
# Setup
## Debian/Ubuntu
**Installing requirements**
 ```
 sudo apt install -y python3 wpasupplicant iw wget
 ```
**Installing Pixiewps**

***Ubuntu 18.04 and above or Debian 10 and above***
 ```
 sudo apt install -y pixiewps
 ```
 
***Other versions***
 ```
 sudo apt install -y build-essential unzip
 wget https://github.com/wiire-a/pixiewps/archive/master.zip && unzip master.zip
 cd pixiewps*/
 make
 sudo make install
 ```
**Getting OneShot**
 ```
 cd ~
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/oneshot.py
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/nl80211_scan.py
 ```
Optional: getting a list of vulnerable to pixie dust devices for highlighting in scan results:
 ```
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/vulnwsc.txt
 ```
## Arch Linux
**Installing requirements**
 ```
 sudo pacman -S wpa_supplicant pixiewps wget python
 ```
**Getting OneShot**
 ```
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/oneshot.py
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/nl80211_scan.py
 ```
Optional: getting a list of vulnerable to pixie dust devices for highlighting in scan results:
 ```
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/vulnwsc.txt
 ```
## Alpine Linux
It can also be used to run on Android devices using [Linux Deploy](https://play.google.com/store/apps/details?id=ru.meefik.linuxdeploy)

**Installing requirements**  
Adding the testing repository:
 ```
 sudo sh -c 'echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories'
 ```
 ```
 sudo apk add python3 wpa_supplicant pixiewps iw
 ```
 **Getting OneShot**
 ```
 sudo wget https://raw.githubusercontent.com/fulvius31/OneShot/master/oneshot.py
 sudo wget https://raw.githubusercontent.com/fulvius31/OneShot/master/nl80211_scan.py
 wget https://raw.githubusercontent.com/fulvius31/OneShot/master/nl80211_scan.py
 ```
Optional: getting a list of vulnerable to pixie dust devices for highlighting in scan results:
 ```
 sudo wget https://raw.githubusercontent.com/fulvius31/OneShot/master/vulnwsc.txt
 ```
## [Termux](https://termux.com/)
Please note that root access is required.  

#### Using installer
 ```
 curl -sSf https://raw.githubusercontent.com/fulvius31/OneShot_Termux_installer/master/installer.sh | bash
 ```
#### Manually
**Installing requirements**
 ```
 pkg install -y root-repo
 pkg install -y git tsu python wpa-supplicant pixiewps iw openssl
 ```
**Getting OneShot**
 ```
 git clone --depth 1 https://github.com/fulvius31/OneShot OneShot
 ```
#### Running
 ```
 sudo python OneShot/oneshot.py -i wlan0 --iface-down -K
 ```

# Usage
```
 oneshot.py <arguments>
 Required arguments:
     -i, --interface=<wlan0>  : Name of the interface to use

 Optional arguments:
     -b, --bssid=<mac>        : BSSID of the target AP
     -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
     -K, --pixie-dust         : Run Pixie Dust attack
     -B, --bruteforce         : Run online bruteforce attack
     --push-button-connect    : Run WPS push button connection

 Advanced arguments:
     -d, --delay=<n>          : Set the delay between pin attempts [0]
     -w, --write              : Write AP credentials to the file on success
     -F, --pixie-force        : Run Pixiewps with --force option (bruteforce full range)
     -X, --show-pixie-cmd     : Always print Pixiewps command
     --vuln-list=<filename>   : Use custom file with vulnerable devices list ['vulnwsc.txt']
     --iface-down             : Down network interface when the work is finished
     -l, --loop               : Run in a loop
     -r, --reverse-scan       : Reverse order of networks in the list of networks. Useful on small displays
     --scanner={auto|nl80211|iw} : Wi-Fi scan backend [auto]. 'auto' uses the built-in
                                nl80211 netlink scanner and falls back to 'iw'; 'nl80211'
                                forces the built-in scanner (no iw binary); 'iw' uses iw.
     --serial=<serial>        : Device serial number — enables the Belkin and Orange PIN algorithms
     --engine={wpa_supplicant|native} : WPS engine [wpa_supplicant]. 'native' is the
                                built-in pure-Python nl80211+EAPOL engine (no wpa_supplicant,
                                no monitor mode; root only). Use with -K (Pixie-Dust) or -p (PIN).
     --mtk-wifi               : Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit
                                (for internal Wi-Fi adapters implemented in MediaTek SoCs). Turn off Wi-Fi in the system settings before using this.
     -v, --verbose            : Verbose output
 ```

## Usage examples
Start Pixie Dust attack on a specified BSSID:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K
 ```
Show avaliable networks and start Pixie Dust attack on a specified network:
 ```
 sudo python3 oneshot.py -i wlan0 -K
 ```
Launch online WPS bruteforce with the specified first half of the PIN:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234
 ```
 Start WPS push button connection:
 ```
 sudo python3 oneshot.py -i wlan0 --pbc
 ```
Scan without the `iw` binary (force the built-in nl80211 scanner):
 ```
 sudo python3 oneshot.py -i wlan0 -K --scanner nl80211
 ```
Run Pixie-Dust with the built-in WPS engine (no `wpa_supplicant`):
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K --engine native
 ```

> **`--engine native` is experimental.** The crypto and protocol layers are
> unit-tested, but the live nl80211 association + EAPOL path is driver-dependent
> and must be validated on real hardware. It needs root, a free `wlan0` (stop
> NetworkManager / the system `wpa_supplicant` first, e.g. `--iface-down`), and
> `pixiewps` for the `-K` crack. If it fails on your adapter, use the default
> `wpa_supplicant` engine.

## Where results are stored
OneShot keeps its data under `~/.OneShot/` (of the user it runs as — i.e. `root` when run with `sudo`):
 - `~/.OneShot/reports/` — recovered credentials (`stored.txt`, `stored.csv`), written with `-w`/`--write`;
 - `~/.OneShot/sessions/` — resumable online-bruteforce sessions;
 - `~/.OneShot/pixiewps/` — PINs calculated by Pixiewps.

## Development
This project uses only the Python standard library. Run the test suite with:
 ```
 python3 -m unittest discover -s tests
 ```
The tests cover the PIN-generation algorithms, the `wpa_supplicant`/`iw` parsers, and the
nl80211 attribute/IE/WPS decoders — no Wi-Fi hardware or root required. They run on every push via
[GitHub Actions](.github/workflows/tests.yml).

## Troubleshooting
#### "RTNETLINK answers: Operation not possible due to RF-kill"
 Just run:
```sudo rfkill unblock wifi```
#### "Device or resource busy (-16)"
 Try disabling Wi-Fi in the system settings and kill the Network manager. Alternatively, you can try running OneShot with ```--iface-down``` argument.
#### The wlan0 interface disappears when Wi-Fi is disabled on Android devices with MediaTek SoC
 Try running OneShot with the `--mtk-wifi` flag to initialize Wi-Fi device driver.
# Acknowledgements
## Special Thanks
* `rofl0r` for initial implementation;
* `Monohrom` for testing, help in catching bugs, some ideas;
* `Wiire` for developing Pixiewps;
* `drydryg` for his amazing work on `rofl0r` repo.
