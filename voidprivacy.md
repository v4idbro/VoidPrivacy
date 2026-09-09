VoidPrivacy V1.0

Terminal-only transparent Tor routing for Linux. No GUI. No manual install.

How it works
On first run VoidPrivacy detects the system package manager (apt, pacman, dnf, zypper or apk) and installs whatever is missing (tor, iptables, curl, obfs4proxy) by itself. All TCP traffic is then redirected through the Tor TransPort. All DNS queries are redirected through the Tor DNSPort. Every connection that does not belong to the Tor process is dropped (kill switch), including IPv6. If a bridges file is present, Tor connects through obfs4 pluggable transports instead of connecting directly to the Tor network, so the ISP only sees ordinary encrypted traffic to a bridge, not a connection to Tor.

Run
sudo python3 voidprivacy.py

Nothing else is required. The banner is printed, dependencies are installed automatically if missing, the kill switch and Tor are started, then it asks how many seconds between circuit rotations. Every time the exit IP changes it prints:
IP changed to <ip>

Optional: hide Tor usage from the ISP
Bridges are obtained from the official Tor Project source, never invented or shared by third parties.
1. Open https://bridges.torproject.org in a browser
2. Request obfs4 bridges
3. sudo mkdir -p /etc/voidprivacy
4. sudo nano /etc/voidprivacy/bridges.txt
5. Paste one bridge line per line, save, run VoidPrivacy again
If this file is missing or empty, VoidPrivacy connects to Tor directly, without bridges.

Stop
Press Ctrl+C. The firewall and torrc are restored automatically and Tor is stopped.
