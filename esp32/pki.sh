#!/usr/bin/env bash
# Certificates for the ESP32 vault (mutual TLS). The board is its own device CA: it signs a device's cert when you
# approve it with its BOOT button, so adding a device needs only the board and that device.
#
#   ./pki.sh server            a server cert for tests/fake_esp.py -> vault/cert.pem (+ vault/cert.h, which a firmware
#                              build copies into a board that has no server cert yet; boards normally make their own)
#   ./pki.sh pair <name>       make THIS machine device <name>: press BOOT on the board first, type the code it
#                              shows, press BOOT again to approve (--force to re-pair an already set up machine)
#   ./pki.sh devices           list paired devices (asks the board)
#   ./pki.sh revoke <name>     lock a device out; press BOOT on the board to confirm
#
# Pairing protocol: see the comment at the top of vault/vault.ino. The device key never leaves this machine.
set -euo pipefail
# Under sudo, HOME can still be the user's: root-owned files in ~/.config/pwvault would lock the user out
[ "$(id -u)" -ne 0 ] || { echo "error: don't run pki.sh with sudo; run it as yourself" >&2; exit 1; }
cd "$(dirname "$0")"
DAYS=3650
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/pwvault"
PAIR_PORT="${PWVAULT_PAIR_PORT:-8444}"  # override for tests (fake_esp.py)
umask 077

die() { echo "error: $*" >&2; exit 1; }
for tool in openssl curl; do
    command -v $tool >/dev/null || die "needs $tool; install it, or run: nix-shell -p openssl curl --run '$0 $*'"
done
[ ! -e "$CONF_DIR/config" ] || [ -r "$CONF_DIR/config" ] ||
    die "can't read $CONF_DIR/config (owned by $(stat -c %U "$CONF_DIR/config")); fix: sudo chown $(id -un): $CONF_DIR/config"
[ ! -e "$CONF_DIR" ] || [ -w "$CONF_DIR" ] ||
    die "can't write to $CONF_DIR (owned by $(stat -c %U "$CONF_DIR")); fix: sudo chown -R $(id -un): $CONF_DIR"
conf_get() { [ -r "$CONF_DIR/config" ] && sed -n "s/^$1=//p" "$CONF_DIR/config" | tail -1 || true; }
# set or replace key=value in this machine's config
conf_set() {
    touch "$CONF_DIR/config" && chmod 600 "$CONF_DIR/config"
    if grep -q "^$1=" "$CONF_DIR/config"; then sed -i "s|^$1=.*|$1=$2|" "$CONF_DIR/config"
    else echo "$1=$2" >> "$CONF_DIR/config"; fi
}
cn_of() { openssl x509 -in "$1" -noout -subject | sed 's/.*CN *= *//'; }
json_field() { sed -n "s/.*\"$2\": *\"\([^\"]*\)\".*/\1/p" <<< "$1"; }  # the board's replies are flat JSON

# curl the board as this device: board <path> [curl args]; prints the body, then the status on its own line
board() {
    local host port
    host=$(conf_get espHost)
    port=$(conf_get espPort)
    [ -n "$host" ] || die "no espHost in $CONF_DIR/config"
    [ -e "$CONF_DIR/device.key" ] || die "this machine isn't paired yet: ./pki.sh pair <name>"
    curl -sS -m 90 -w '\n%{http_code}' --cacert "$CONF_DIR/server.pem" --cert "$CONF_DIR/device.pem" \
        --key "$CONF_DIR/device.key" --resolve "pwvault.local:${port:-443}:$host" "${@:2}" \
        "https://pwvault.local:${port:-443}$1" || die "can't reach the board at $host:${port:-443}"
}

case "${1:-}" in
server)
    [ -f vault/cert.h ] && die "vault/cert.h exists; delete it first (every client pins the current cert.pem)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days $DAYS \
        -subj "/CN=pwvault.local" -addext "subjectAltName=DNS:pwvault.local" \
        -keyout vault/key.pem -out vault/cert.pem 2>/dev/null
    printf 'const char CERT_PEM[] = R"(%s\n)";\nconst char KEY_PEM[] = R"(%s\n)";\n' \
        "$(cat vault/cert.pem)" "$(cat vault/key.pem)" > vault/cert.h
    echo "wrote vault/cert.h and vault/cert.pem"
    ;;
pair)
    name="${2:-}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]] || die "name: 1-20 chars of a-z 0-9 - (it is shown on the OLED)"
    if [ -e "$CONF_DIR/device.key" ] && [ "${3:-}" != --force ]; then
        die "this machine is already set up as '$(cn_of "$CONF_DIR/device.pem")' (add --force to re-pair)"
    fi
    host=$(conf_get espHost)
    [ -n "$host" ] || read -rp "board address (the IP on the OLED): " host
    [ -n "$host" ] || die "need the board address"
    tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT

    # The cert the pairing port presents. Unverified here: the macs below prove it's the board's.
    openssl s_client -connect "$host:$PAIR_PORT" -servername pwvault.local </dev/null 2>/dev/null |
        openssl x509 > "$tmp/server.pem" 2>/dev/null ||
        die "no pairing port at $host:$PAIR_PORT: press BOOT on the board (it then shows a code) and retry"
    fp=$(openssl x509 -in "$tmp/server.pem" -outform DER | sha256sum | cut -d' ' -f1)
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$tmp/device.key"
    csr=$(openssl req -new -key "$tmp/device.key" -subj "/CN=$name" -outform DER | base64 -w0)

    code="${PWVAULT_CODE:-}"
    [ -n "$code" ] || read -rp "code on the OLED: " code
    code=$(tr -d ' -' <<< "$code" | tr 'a-z' 'A-Z' | tr 'ILO' '110')  # Crockford base32: I/L read as 1, O as 0
    [ ${#code} -eq 16 ] || die "the code has 16 characters"
    mac() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$code" | awk '{print $NF}'; }
    nl=$'\n'

    echo "now press BOOT on the board to approve '$name'"
    resp=$(curl -sS -m 90 -w '\n%{http_code}' --cacert "$tmp/server.pem" \
        --resolve "pwvault.local:$PAIR_PORT:$host" -H 'Content-Type: application/json' \
        -d "{\"name\":\"$name\",\"csr\":\"$csr\",\"mac\":\"$(mac "pwvault-pair-req$nl$fp$nl$name$nl$csr")\"}" \
        "https://pwvault.local:$PAIR_PORT/pair") || die "lost the board"
    body=${resp%"$nl"*}
    [ "${resp##*"$nl"}" = 200 ] || die "board: $(json_field "$body" error). Press BOOT to start over."
    cert=$(json_field "$body" cert)
    [ "$(json_field "$body" mac)" = "$(mac "pwvault-pair-resp$nl$fp$nl$cert")" ] ||
        die "the reply isn't signed with the code: someone may be intercepting. Nothing was installed."
    base64 -d <<< "$cert" | openssl x509 -inform DER > "$tmp/device.pem"
    [ "$(openssl x509 -in "$tmp/device.pem" -noout -pubkey)" = "$(openssl pkey -in "$tmp/device.key" -pubout)" ] ||
        die "the board signed a different key"

    mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
    for f in server.pem device.pem device.key; do install -m 600 "$tmp/$f" "$CONF_DIR/$f"; done
    conf_set espHost "$host"
    case $(board /meta -o /dev/null | tail -1) in
    200) echo "✓ paired as '$name'; start the app and unlock with your master password" ;;
    404) echo "✓ paired as '$name' (no vault on the board yet: the app will create one)" ;;
    *) echo "✗ paired as '$name', but the board refuses this device on port $(conf_get espPort)" ;;
    esac
    ;;
devices)
    resp=$(board /devices)
    [ "${resp##*$'\n'}" = 200 ] || die "board: $(json_field "${resp%$'\n'*}" error)"
    you=$(json_field "$resp" you)
    grep -o '{[^}]*}' <<< "$resp" | while read -r obj; do  # [{"name": .., "seen": <unix time, 0 = unknown>}]
        n=$(json_field "$obj" name)
        seen=$(sed -n 's/.*"seen": *\([0-9]*\).*/\1/p' <<< "$obj")
        when=$([ "${seen:-0}" -gt 0 ] && date -d "@$seen" '+last seen %F %H:%M' || echo 'not seen since the board started')
        printf '%-20s %s%s\n' "$n" "$when" "$([ "$n" = "$you" ] && echo '  (this machine)')"
    done
    ;;
revoke)
    name="${2:-}"
    [ -n "$name" ] || die "usage: ./pki.sh revoke <name>"
    resp=$(board "/devices/$name" -X DELETE)
    case ${resp##*$'\n'} in 200 | 202) ;; *) die "board: $(json_field "${resp%$'\n'*}" error)" ;; esac
    echo "now press BOOT on the board to confirm revoking '$name' (within a minute)"
    for _ in $(seq 65); do  # the board revokes on the press; watch the list until the name is gone
        grep -q "\"name\": *\"$name\"" <<< "$(board /devices)" || { echo "revoked $name"; exit 0; }
        sleep 1
    done
    die "BOOT wasn't pressed in time; $name still has access"
    ;;
*)
    sed -n '2,11p' "$(basename "$0")" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
