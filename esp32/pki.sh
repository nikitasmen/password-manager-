#!/usr/bin/env bash
# Certificates for the ESP32 vault (mutual TLS). CA and device keys live in esp32/pki/ (gitignored).
#
#   ./pki.sh server            server cert the clients pin      -> vault/cert.h, vault/cert.pem
#   ./pki.sh init              device CA the ESP32 trusts       -> pki/ca.{key,pem}, vault/devices.h (reflash)
#   ./pki.sh enroll <name>     new device: one encrypted file + one-time code to carry to it
#   ./pki.sh import <file>     on the new device: asks for the code, installs, checks the board is reachable
#   ./pki.sh install <name>    set up THIS machine as <name> (no file needed)
#   ./pki.sh revoke <name>     block a device                   -> vault/devices.h (reflash)
#   ./pki.sh list
#
# Enrolling needs no reflash: the board trusts anything the CA signed. The CA key can mint devices, so keep
# pki/ca.key private. The board address put into enrollment files comes from this machine's config (espHost).
set -euo pipefail
# Under sudo, HOME can still be the user's: root-owned files in ~/.config/pwvault would lock the user out
[ "$(id -u)" -ne 0 ] || { echo "error: don't run pki.sh with sudo; run it as yourself" >&2; exit 1; }
ORIG_PWD=$PWD
cd "$(dirname "$0")"
PKI="${PWVAULT_PKI:-pki}"  # override for tests
DAYS=3650
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/pwvault"
umask 077

die() { echo "error: $*" >&2; exit 1; }
ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$1"; }
conf_get() { [ -r "$CONF_DIR/config" ] && sed -n "s/^$1=//p" "$CONF_DIR/config" | tail -1 || true; }
# set or replace key=value in this machine's config
conf_set() {
    touch "$CONF_DIR/config" && chmod 600 "$CONF_DIR/config"
    if grep -q "^$1=" "$CONF_DIR/config"; then sed -i "s|^$1=.*|$1=$2|" "$CONF_DIR/config"
    else echo "$1=$2" >> "$CONF_DIR/config"; fi
}
# The board's address: from config, else ask (an empty answer leaves it unset)
ask_host() {
    local host
    host=$(conf_get espHost)
    if [ -z "$host" ] && [ -t 0 ]; then read -rp "board address (the IP on the OLED; Enter to skip): " host; fi
    echo "$host"
}

# vault/devices.h: the CA the board verifies clients against, plus revoked device names
write_header() {
    local name
    {
        printf 'const char DEVICE_CA_PEM[] = R"(%s\n)";\n' "$(cat $PKI/ca.pem)"
        printf 'const char* const REVOKED_DEVICES[] = {'
        while read -r name; do [ -n "$name" ] && printf '"%s", ' "$name"; done < "$PKI/revoked.txt"
        printf 'nullptr};\n'
    } > vault/devices.h
}

# Issue <name> unless it exists already
issue() {
    local name=$1
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]] || die "name: 1-20 chars of a-z 0-9 - (it is shown on the OLED)"
    [ -f $PKI/ca.key ] || die "run ./pki.sh init first"
    grep -qx "$name" $PKI/revoked.txt && die "$name was revoked; pick a new name"
    [ -e $PKI/devices/$name.pem ] && return
    ec_key $PKI/devices/$name.key
    openssl req -new -key $PKI/devices/$name.key -subj "/CN=$name" 2>/dev/null |
        openssl x509 -req -CA $PKI/ca.pem -CAkey $PKI/ca.key -CAcreateserial -days $DAYS \
            -extfile <(printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n') \
            -out $PKI/devices/$name.pem 2>/dev/null
    rm -f $PKI/ca.srl
}

# Everything a device needs, in <dir>: server.pem device.pem device.key, and `settings` (espHost/espPort)
stage() {
    local name=$1 dir=$2 host=$3
    cp vault/cert.pem "$dir/server.pem"
    cp $PKI/devices/$name.pem "$dir/device.pem"
    cp $PKI/devices/$name.key "$dir/device.key"
    printf 'espHost=%s\nespPort=%s\n' "$host" "$(conf_get espPort)" > "$dir/settings"
}

# Install a staged <dir> into this machine's config folder, then check the board accepts it
install_staged() {
    local dir=$1 force=${2:-} key val host port code name
    if [ -e "$CONF_DIR/device.key" ] && [ "$force" != --force ]; then
        die "this machine is already set up as '$(openssl x509 -in "$CONF_DIR/device.pem" -noout -subject | sed 's/.*CN *= *//')' (add --force to replace)"
    fi
    mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
    for f in server.pem device.pem device.key; do install -m 600 "$dir/$f" "$CONF_DIR/$f"; done
    touch "$CONF_DIR/config" && chmod 600 "$CONF_DIR/config"
    while IFS='=' read -r key val; do  # espHost/espPort from the file override this machine's config
        [ -z "$val" ] || conf_set "$key" "$val"
    done < "$dir/settings"
    name=$(openssl x509 -in "$CONF_DIR/device.pem" -noout -subject | sed 's/.*CN *= *//')
    host=$(ask_host)
    [ -z "$host" ] || conf_set espHost "$host"
    port=$(conf_get espPort)
    port=${port:-443}
    echo "this machine is now '$name' ($CONF_DIR)"
    [ -n "$host" ] || { echo "no board address set: add espHost=<IP on the OLED> to $CONF_DIR/config"; return; }
    command -v curl >/dev/null || { echo "(install curl to have the board connection checked)"; return; }
    code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' --cacert "$CONF_DIR/server.pem" --cert "$CONF_DIR/device.pem" \
        --key "$CONF_DIR/device.key" --resolve "pwvault.local:$port:$host" "https://pwvault.local:$port/meta" || true)
    case $code in
    200) echo "✓ board at $host accepts this device; start the app and unlock with your master password" ;;
    404) echo "✓ board at $host accepts this device (no vault on it yet: the app will create one)" ;;
    403) echo "✗ board at $host says '$name' is revoked" ;;
    *) echo "✗ can't reach the board at $host:$port (not on its network? wrong espHost?); files are installed anyway" ;;
    esac
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
init)
    [ -f $PKI/ca.key ] && die "$PKI/ca.key exists; a new CA would invalidate every device"
    mkdir -p $PKI/devices
    ec_key $PKI/ca.key
    openssl req -x509 -new -key $PKI/ca.key -days $DAYS -subj "/CN=pwvault device CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out $PKI/ca.pem
    : > $PKI/revoked.txt
    write_header
    echo "device CA created; reflash the ESP32, then: ./pki.sh install <name-of-this-machine>"
    ;;
enroll)
    name="${2:-}"
    issue "$name"
    host=$(ask_host)
    [ -n "$host" ] || echo "note: no board address in the file; the new device will be asked for it on import"
    tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT
    stage "$name" "$tmp" "$host"
    out="$ORIG_PWD/$name.pwvault"
    code=$(openssl rand -hex 8 | sed 's/..../&-/g; s/-$//')
    tar -C "$tmp" -c server.pem device.pem device.key settings |
        PWVAULT_CODE=$code openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:PWVAULT_CODE -out "$out"
    echo "enrollment file: $out"
    echo "one-time code:   $code"
    echo
    echo "Copy the file to the new device (USB, scp, cloud: it's useless without the code), then run there:"
    echo "  esp32/pki.sh import $name.pwvault"
    echo "Delete the file afterwards."
    ;;
import)
    file="${2:-}"
    [ -n "$file" ] || die "usage: ./pki.sh import <file.pwvault> [--force]"
    [[ "$file" = /* ]] || file="$ORIG_PWD/$file"
    [ -f "$file" ] || die "no such file: $file"
    code="${PWVAULT_CODE:-}"
    [ -n "$code" ] || { read -rsp "one-time code: " code; echo; }
    tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT
    PWVAULT_CODE=$code openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:PWVAULT_CODE -in "$file" 2>/dev/null |
        tar -C "$tmp" -x 2>/dev/null || die "wrong code, or not an enrollment file"
    install_staged "$tmp" "${3:-}"
    echo "You can delete $file now."
    ;;
install)
    name="${2:-}"
    [ -e $PKI/devices/$name.pem ] || issue "$name"
    tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT
    stage "$name" "$tmp" "$(conf_get espHost)"
    install_staged "$tmp" "${3:-}"
    ;;
revoke)
    name="${2:-}"
    [ -e $PKI/devices/$name.pem ] || die "no device named '$name'"
    grep -qx "$name" $PKI/revoked.txt && die "$name is already revoked"
    echo "$name" >> $PKI/revoked.txt
    write_header
    echo "revoked $name; reflash the ESP32 for it to take effect"
    ;;
list)
    for f in $PKI/devices/*.pem; do
        [ -e "$f" ] || { echo "(no devices)"; break; }
        n=$(basename "$f" .pem)
        printf '%-20s %s\n' "$n" "$(grep -qx "$n" $PKI/revoked.txt && echo revoked || echo active)"
    done
    ;;
*)
    sed -n '2,13p' "$(basename "$0")" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
