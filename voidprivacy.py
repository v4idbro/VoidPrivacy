#!/usr/bin/env python3

import os
import socket
import subprocess
import sys
import time

TRANS_PORT = "9040"
DNS_PORT = "5353"
CTRL_PORT = 9051
TORRC_PATH = "/etc/tor/torrc"
TORRC_BACKUP = "/etc/tor/torrc.voidprivacy.bak"
STATE_DIR = "/var/lib/voidprivacy"
BRIDGES_FILE = "/etc/voidprivacy/bridges.txt"
IPTABLES_BACKUP = f"{STATE_DIR}/iptables.rules.bak"
IP6TABLES_BACKUP = f"{STATE_DIR}/ip6tables.rules.bak"

BANNER = "\033[1;32;40m\n" \
"#   #  ###  ##### ####     ####  ####  ##### #   #  ###   #### #   # \n" \
"#   # #   #   #   #   #    #   # #   #   #   #   # #   # #      # #  \n" \
"#   # #   #   #   #   #    ####  ####    #   #   # ##### #       #   \n" \
" # #  #   #   #   #   #    #     #  #    #    # #  #   # #       #   \n" \
"  #    ###  ##### ####     #     #   # #####   #   #   #  ####   #   \n" \
"                V 1.0\n" \
"\033[0m" \
"\033[0;37mhttps://github.com/v4idbro\033[0m\n"


def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def require_root():
    if os.geteuid() != 0:
        sys.exit(1)


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


def package_manager():
    for pm in ("apt-get", "pacman", "dnf", "zypper", "apk"):
        if run(f"command -v {pm}", check=False).returncode == 0:
            return pm
    return None


def install_dependencies():
    binaries = {
        "tor": "tor",
        "iptables": "iptables",
        "curl": "curl",
        "obfs4proxy": "obfs4proxy",
    }
    missing = [pkg for binary, pkg in binaries.items()
               if run(f"command -v {binary}", check=False).returncode != 0]
    if not missing:
        return
    pm = package_manager()
    if not pm:
        return
    pkgs = " ".join(sorted(set(missing)))
    if pm == "apt-get":
        run("apt-get update -y", check=False)
        run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}", check=False)
    elif pm == "pacman":
        run(f"pacman -Sy --noconfirm {pkgs}", check=False)
    elif pm == "dnf":
        run(f"dnf install -y {pkgs}", check=False)
    elif pm == "zypper":
        run(f"zypper --non-interactive install {pkgs}", check=False)
    elif pm == "apk":
        run(f"apk add --no-cache {pkgs}", check=False)


def detect_tor_user():
    for name in ("debian-tor", "tor", "_tor", "toranon"):
        try:
            run(f"id -u {name}")
            return name
        except subprocess.CalledProcessError:
            continue
    out = run("ps -o user= -C tor", check=False).stdout.decode().strip().splitlines()
    return out[0] if out else None


def detect_obfs4_path():
    out = run("command -v obfs4proxy", check=False).stdout.decode().strip()
    return out if out else None


def write_torrc():
    if not os.path.exists(TORRC_BACKUP):
        run(f"cp {TORRC_PATH} {TORRC_BACKUP}", check=False)
    config = f"""
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort {TRANS_PORT}
DNSPort {DNS_PORT}
SocksPort 9050
ControlPort {CTRL_PORT}
CookieAuthentication 1
"""
    obfs4_path = detect_obfs4_path()
    if obfs4_path and os.path.exists(BRIDGES_FILE):
        with open(BRIDGES_FILE) as bf:
            bridges = [l.strip() for l in bf if l.strip() and not l.strip().startswith("#")]
        if bridges:
            config += f"\nUseBridges 1\nClientTransportPlugin obfs4 exec {obfs4_path}\n"
            for b in bridges:
                config += f"Bridge {b}\n"
    with open(TORRC_PATH, "a") as f:
        f.write(config)


def restore_torrc():
    if os.path.exists(TORRC_BACKUP):
        run(f"cp {TORRC_BACKUP} {TORRC_PATH}", check=False)


def backup_firewall():
    ensure_state_dir()
    run(f"iptables-save > {IPTABLES_BACKUP}", check=False)
    run(f"ip6tables-save > {IP6TABLES_BACKUP}", check=False)


def restore_firewall():
    if os.path.exists(IPTABLES_BACKUP):
        run(f"iptables-restore < {IPTABLES_BACKUP}", check=False)
    else:
        run("iptables -F", check=False)
        run("iptables -t nat -F", check=False)
        run("iptables -P INPUT ACCEPT", check=False)
        run("iptables -P OUTPUT ACCEPT", check=False)
        run("iptables -P FORWARD ACCEPT", check=False)
    if os.path.exists(IP6TABLES_BACKUP):
        run(f"ip6tables-restore < {IP6TABLES_BACKUP}", check=False)
    else:
        run("ip6tables -F", check=False)
        run("ip6tables -P INPUT ACCEPT", check=False)
        run("ip6tables -P OUTPUT ACCEPT", check=False)
        run("ip6tables -P FORWARD ACCEPT", check=False)


def apply_firewall(tor_user):
    rules = [
        "iptables -F",
        "iptables -t nat -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT DROP",
        f"iptables -t nat -A OUTPUT -m owner --uid-owner {tor_user} -j RETURN",
        f"iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports {DNS_PORT}",
        f"iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports {TRANS_PORT}",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        f"iptables -A OUTPUT -m owner --uid-owner {tor_user} -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -j DROP",
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -j DROP",
        "ip6tables -F",
        "ip6tables -P INPUT DROP",
        "ip6tables -P FORWARD DROP",
        "ip6tables -P OUTPUT DROP",
    ]
    for r in rules:
        run(r)


def start_tor_service():
    run("systemctl restart tor", check=False)
    for _ in range(15):
        try:
            with socket.create_connection(("127.0.0.1", int(TRANS_PORT)), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def stop_tor_service():
    run("systemctl stop tor", check=False)


def newnym():
    cookie_path = "/var/run/tor/control.authcookie"
    if not os.path.exists(cookie_path):
        cookie_path = "/run/tor/control.authcookie"
    if not os.path.exists(cookie_path):
        return False
    with open(cookie_path, "rb") as f:
        cookie = f.read().hex()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", CTRL_PORT))
    s.sendall(f'AUTHENTICATE {cookie}\r\n'.encode())
    s.recv(1024)
    s.sendall(b'SIGNAL NEWNYM\r\n')
    reply = s.recv(1024)
    s.close()
    return b"250" in reply


def current_ip():
    try:
        out = run('curl -s --max-time 6 https://icanhazip.com', check=False).stdout.decode().strip()
        return out if out else None
    except subprocess.CalledProcessError:
        return None


def rotation_loop(interval):
    last_ip = current_ip()
    if last_ip:
        print(f"IP changed to {last_ip}")
    while True:
        time.sleep(interval)
        newnym()
        time.sleep(1)
        ip = current_ip()
        if ip and ip != last_ip:
            print(f"IP changed to {ip}")
            last_ip = ip


def cleanup():
    stop_tor_service()
    restore_firewall()
    restore_torrc()


def main():
    require_root()
    print(BANNER)
    install_dependencies()
    tor_user = detect_tor_user()
    if not tor_user:
        sys.exit(1)
    write_torrc()
    backup_firewall()
    apply_firewall(tor_user)
    if not start_tor_service():
        cleanup()
        sys.exit(1)
    print("[active]")
    try:
        interval = int(input("How much time changes (seconds): "))
    except ValueError:
        interval = 60
    if interval <= 0:
        interval = 60
    try:
        rotation_loop(interval)
    except KeyboardInterrupt:
        cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()
