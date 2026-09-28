#!/usr/bin/env bash
# Certificates for the ESP32 vault (mutual TLS). Everything lands in esp32/pki/ (gitignored: it holds private keys).
#
#   ./pki.sh server          server cert the clients pin      -> vault/cert.h, vault/cert.pem
#   ./pki.sh init            device CA the ESP32 trusts       -> pki/ca.{key,pem}, vault/devices.h
#   ./pki.sh add <name>      certificate for one device       -> pki/devices/<name>.{key,pem}
#   ./pki.sh revoke <name>   block a device                   -> vault/devices.h (then reflash)
#   ./pki.sh list
#
# Reflash after `init` and `revoke`. `add` needs no reflash: the board trusts anything the CA signed.
# The CA key can mint new devices: keep pki/ca.key private (offline is best once your devices exist).
set -euo pipefail
cd "$(dirname "$0")"
PKI=pki
DAYS=3650
umask 077

die() { echo "error: $*" >&2; exit 1; }
ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$1"; }

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

case "${1:-}" in
server)
    [ -f vault/cert.h ] && die "vault/cert.h exists; delete it first (every client pins the current cert.pem)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days $DAYS \
        -subj "/CN=pwvault.local" -addext "subjectAltName=DNS:pwvault.local" \
        -keyout vault/key.pem -out vault/cert.pem 2>/dev/null
    printf 'const char CERT_PEM[] = R"(%s\n)";\nconst char KEY_PEM[] = R"(%s\n)";\n' \
        "$(cat vault/cert.pem)" "$(cat vault/key.pem)" > vault/cert.h
    echo "wrote vault/cert.h and vault/cert.pem (give cert.pem to every client)"
    ;;
init)
    [ -f $PKI/ca.key ] && die "$PKI/ca.key exists; a new CA would invalidate every device"
    mkdir -p $PKI/devices
    ec_key $PKI/ca.key
    openssl req -x509 -new -key $PKI/ca.key -days $DAYS -subj "/CN=pwvault device CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out $PKI/ca.pem
    : > $PKI/revoked.txt
    write_header
    echo "device CA created; reflash the ESP32, then: ./pki.sh add <device-name>"
    ;;
add)
    name="${2:-}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]] || die "name: 1-20 chars of a-z 0-9 - (it is shown on the OLED)"
    [ -f $PKI/ca.key ] || die "run ./pki.sh init first"
    [ -e $PKI/devices/$name.pem ] && die "$name already exists"
    grep -qx "$name" $PKI/revoked.txt && die "$name was revoked; pick a new name"
    ec_key $PKI/devices/$name.key
    openssl req -new -key $PKI/devices/$name.key -subj "/CN=$name" 2>/dev/null |
        openssl x509 -req -CA $PKI/ca.pem -CAkey $PKI/ca.key -CAcreateserial -days $DAYS \
            -extfile <(printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n') \
            -out $PKI/devices/$name.pem 2>/dev/null
    rm -f $PKI/ca.srl
    echo "issued $name. On that device, in .config:"
    echo "  espClientCert=$PWD/$PKI/devices/$name.pem"
    echo "  espClientKey=$PWD/$PKI/devices/$name.key"
    echo "(copy both files to the device if it's another machine; the .key is its secret)"
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
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
