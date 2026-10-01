# Using the vault away from home

The app is local-first: away from home it keeps working on its local copy and syncs when it's back on your network. Set this up only if you want devices to sync while away.

**Don't port-forward the board.** Its TLS stack never gets security updates, and with two sockets and a ~0.5 s handshake it's easy to knock offline. Instead, run a WireGuard server on an always-on machine at home. Only WireGuard's UDP port is open to the internet, and WireGuard drops every packet that isn't signed with a known key, so scanners see nothing. Your devices join the tunnel and reach the board at its LAN IP. The app config doesn't change.

```
phone (4G) ──UDP 51820──▶ router ──▶ Pi (WireGuard, 10.8.0.1) ──TCP 443──▶ board (192.168.x.y)
```

## Requirements

- **A public IP, not CGNAT.** The WAN IP on your router's status page must match `curl ifconfig.me`. If they differ, or the WAN IP is in `100.64.0.0/10` or `10.0.0.0/8`, inbound ports can't work: use a relay-based mesh instead ([Tailscale subnet router](https://tailscale.com/kb/1019/subnets), Headscale, NetBird or ZeroTier).
- **An always-on Linux machine on the LAN** (Raspberry Pi OS or Debian). It can run other things, Docker included. A laptop doesn't work, because it's away or asleep.
- If your router can run WireGuard itself (OpenWrt, some ASUS and Fritz!Box models), use that instead and skip the script.

## 1. Router

- **DHCP reservations** for the board and the WireGuard machine, so their addresses never change.
- **Port forwarding** (sometimes called port mapping): **UDP** 51820 → the WireGuard machine's LAN IP, port 51820. WireGuard has no TCP mode.
- **Dynamic DNS**, if your public IP changes (it usually does on home lines): use the router's DDNS setting, or on the WireGuard machine create a free [DuckDNS](https://www.duckdns.org) name and add this line with `crontab -e`:
  ```
  */5 * * * * curl -s "https://www.duckdns.org/update?domains=NAME&token=TOKEN&ip=" >/dev/null
  ```
- **Remote management off.** If `http://<your DDNS name>` shows the router's login page **from mobile data**, the router's admin page is open to the internet. From your home Wi-Fi it's normal.

## 2. WireGuard server

Copy [`esp32/wg-setup.sh`](../esp32/wg-setup.sh) to the machine with `scp`. Don't paste it into a terminal editor: wrapped lines break it. Then:

```bash
sudo ENDPOINT=NAME.duckdns.org:51820 BOARD=192.168.2.5 ./wg-setup.sh phone:2 laptop:3
```

The first run installs WireGuard, generates the server key and starts `wg-quick@wg0`. It allows the tunnel to reach only the board's port (`BOARD_PORT`, 443 by default). Every run adds the devices you name and prints a QR code for each. Add a device later with `sudo ENDPOINT=… BOARD=… ./wg-setup.sh tablet:4`.

## 3. Devices

- **Android:** in the [WireGuard app](https://www.wireguard.com/install/), tap + → Scan from QR code.
- **Linux:** copy `/etc/wireguard/<name>.conf` to the device, then run `nmcli connection import type wireguard file <name>.conf`, or put it in `/etc/wireguard/` and use `wg-quick up <name>`.
- Once a device has imported its config, delete `/etc/wireguard/<name>.conf` from the server, because it contains that device's private key.

Never paste `wg0.conf`, `server.key` or a device `.conf` anywhere. `sudo wg show` prints only public keys and is safe to share.

**Turn the tunnel off on your home Wi-Fi.** Each device's config sends the board's IP through the tunnel, and the tunnel connects to your public IP. At home, that works only if the router supports NAT loopback (hairpin NAT), and many ISP routers don't. If yours doesn't, the board is unreachable at home while the tunnel is up. On Android, the [WG Tunnel](https://github.com/wgtunnel/android) app can turn the tunnel off automatically on chosen Wi-Fi networks.

## 4. Test

Phone on mobile data with Wi-Fi off, tunnel on, then sync in the app. On the server, `sudo wg show` should list `latest handshake` and `transfer` for the phone.

| Symptom | Cause | Check |
|---|---|---|
| No `latest handshake` | packets don't reach the server | port forward is UDP and points at the right IP; `Endpoint` resolves to your public IP (`getent hosts NAME.duckdns.org`) |
| Handshake, phone receives ~0 bytes | the server doesn't forward to the board | `sysctl net.ipv4.ip_forward` is 1; `sudo iptables -S FORWARD` shows the `wg0` rules above Docker's |
| Traffic both ways, app says unreachable | wrong board address or port | from the server: `curl -sk https://BOARD/` should get an answer; the app's host matches `BOARD` |
| Fails only at home | no NAT loopback | turn the tunnel off on home Wi-Fi |

## Removing a device

On the server, delete its `[Peer]` block from `/etc/wireguard/wg0.conf` and its `<name>.pub`, then run `sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'`. A lost phone should also be revoked on the board (Devices in the app, or `esp32/pki.sh revoke <name>`): the tunnel only gets it to the board, but its pairing certificate is what lets it in.
