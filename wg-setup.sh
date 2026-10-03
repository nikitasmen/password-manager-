#!/usr/bin/env bash
# WireGuard server for reaching the vault board from outside your home network (docs/REMOTE_ACCESS.md).
# Run on an always-on Debian/Raspberry Pi OS machine on the same LAN as the board. The first run sets up the
# server; every run adds the devices named on the command line and prints a QR code for each.
#
#   sudo ENDPOINT=myhome.duckdns.org:51820 BOARD=192.168.2.5 ./wg-setup.sh phone:2 laptop:3
#                                          name:n -> the device gets tunnel IP 10.8.0.n
#
# The tunnel reaches only BOARD:BOARD_PORT; clients route only BOARD through it.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "error: run with sudo" >&2; exit 1; }
: "${ENDPOINT:?set ENDPOINT=<public name or IP>:51820}"
: "${BOARD:?set BOARD=<the board LAN IP>}"
BOARD_PORT="${BOARD_PORT:-443}"
mkdir -p /etc/wireguard && cd /etc/wireguard && umask 077

if [ ! -f wg0.conf ]; then
    apt install -y wireguard iptables qrencode
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf && sysctl --system >/dev/null
    wg genkey | tee server.key | wg pubkey > server.pub
    LAN=$(ip route | awk '/default/{print $5; exit}')
    # -I puts the FORWARD rules ahead of Docker's, which sets the FORWARD policy to DROP
    cat > wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $(cat server.key)
PostUp   = iptables -I FORWARD -i wg0 -o $LAN -d $BOARD -p tcp --dport $BOARD_PORT -j ACCEPT; iptables -I FORWARD -i $LAN -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $LAN -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o $LAN -d $BOARD -p tcp --dport $BOARD_PORT -j ACCEPT; iptables -D FORWARD -i $LAN -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $LAN -j MASQUERADE
EOF
    systemctl enable --now wg-quick@wg0
fi

for p in "$@"; do
    name=${p%%:*}; n=${p##*:}
    if [ -f "$name.pub" ]; then echo "$name exists, skipping"; continue; fi
    wg genkey | tee "$name.key" | wg pubkey > "$name.pub"
    printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = 10.8.0.%s/32\n' "$name" "$(cat "$name.pub")" "$n" >> wg0.conf
    cat > "$name.conf" <<EOF
[Interface]
PrivateKey = $(cat "$name.key")
Address = 10.8.0.$n/32

[Peer]
PublicKey = $(cat server.pub)
Endpoint = $ENDPOINT
AllowedIPs = $BOARD/32
PersistentKeepalive = 25
EOF
    rm "$name.key"  # the private key now lives only in the client config
    echo "== $name  (/etc/wireguard/$name.conf: import it, then delete it)"
    qrencode -t ansiutf8 < "$name.conf"
done

wg syncconf wg0 <(wg-quick strip wg0)
wg show
