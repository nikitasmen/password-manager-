#!/usr/bin/env python3
"""A stand-in for the ESP32 store (docs/PROTOCOL.md §6-7), for testing clients without touching the real board.

Same API, mutual TLS, pairing, revocation and merge rule as esp32/vault/vault.ino; state is kept in memory.
Its device CA lives in --ca-dir (made on first use, with openssl). Pairing is always open on --pair-port with the
printed code, and the "BOOT press" is automatic: pair and revoke requests are approved at once.

  python3 tests/fake_esp.py --port 8443 --cert esp32/vault/cert.pem --key esp32/vault/key.pem \
      --ca-dir <dir> [--code 0123456789ABCDEF]
Pair a sandboxed client (XDG_CONFIG_HOME, espHost=127.0.0.1, espPort=8443) with
  PWVAULT_PAIR_PORT=8444 PWVAULT_CODE=<code> esp32/pki.sh pair <name>
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAX_BODY, MAX_BATCH = 16 * 1024, 32
ID = re.compile(r"^[0-9a-f]{32}$")
state = {"meta": None, "seq": 0, "entries": {}}


def newer(a, b):
    """PROTOCOL.md §5 merge rule: does record a replace record b?"""
    return (a["updated"], a["data"].encode()) > (b["updated"], b["data"].encode())


lock = threading.Lock()  # one request at a time touches state, like the board's mutex
devices = {}  # name -> hex SHA-256 of its current cert; not in here = revoked
seen = {}  # name -> unix time of its last request
pins = {}  # name -> {secret, verifier, fails}, like /pin/<name> on the board
PIN_TRIES = 5
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
ctx_holder = {}
pairing = {}  # code, server_fp, ca_dir


def make_ca(d):
    if not os.path.exists(f"{d}/ca.pem"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "3650", "-subj", "/CN=pwvault device CA", "-keyout", f"{d}/ca.key",
                        "-out", f"{d}/ca.pem", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                        "-addext", "keyUsage=critical,keyCertSign"], check=True, capture_output=True)


def sign(name, csr_der):
    """Sign a CSR (DER) as CN=name, like issueCert() on the board. Returns the cert as DER."""
    d = pairing["ca_dir"]
    with tempfile.TemporaryDirectory() as t:
        open(f"{t}/csr.der", "wb").write(csr_der)
        open(f"{t}/ext", "w").write("extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
        subprocess.run(["openssl", "x509", "-req", "-inform", "DER", "-in", f"{t}/csr.der", "-CA", f"{d}/ca.pem",
                        "-CAkey", f"{d}/ca.key", "-set_serial", str(secrets.randbits(120)), "-days", "3650",
                        "-subj", f"/CN={name}", "-extfile", f"{t}/ext", "-outform", "DER", "-out", f"{t}/crt"],
                       check=True, capture_output=True)
        return open(f"{t}/crt", "rb").read()


def mac(msg):
    return hmac.new(pairing["code"].encode(), msg.encode(), hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, like the board

    def setup(self):
        try:
            self.request = ctx_holder["ctx"].wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):  # no/foreign client certificate: refused in the handshake
            self.request.close()
            raise
        super().setup()

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def device(self):
        """The device name, if its cert is the current one for that name (see authDevice() on the board)."""
        subject = dict(x[0] for x in self.connection.getpeercert()["subject"])
        name = subject.get("commonName")
        fp = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        if devices.get(name) != fp:
            return None
        seen[name] = int(time.time())
        return name

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            self.rfile.read(n)
            return self.reply(413, {"error": "body too large"})
        try:
            return json.loads(self.rfile.read(n) or b"null")
        except ValueError:
            return self.reply(400, {"error": "bad json"})

    def handle_request(self, method):
        who = self.device()
        if not who:
            self.reply(403, {"error": "device revoked"})
            self.close_connection = True
            return
        url = urlparse(self.path)
        route = (method, url.path)
        if route == ("GET", "/meta"):
            return self.reply(200, state["meta"]) if state["meta"] else self.reply(404, {"error": "no vault yet"})
        if route == ("GET", "/devices"):
            return self.reply(200, {"devices": [{"name": n, "seen": seen.get(n, 0)} for n in devices], "you": who})
        if method == "DELETE" and url.path.startswith("/devices/"):
            name = url.path[len("/devices/"):]
            if name not in devices:
                return self.reply(404, {"error": "no such device"})
            del devices[name]
            pins.pop(name, None)
            print(f"[{who}] revoked {name}", flush=True)
            return self.reply(202, {"pending": True})  # like the board, then "BOOT" is pressed at once
        if route == ("POST", "/pair/open"):  # pairing is always open here; hand out its code, as the board would
            print(f"[{who}] opened pairing", flush=True)
            return self.reply(200, {"code": pairing["code"], "qr": f"PWVAULT:127.0.0.1:{pairing['code']}", "seconds": 120})
        if route in (("PUT", "/pin"), ("POST", "/pin")):
            req = self.body()
            if not isinstance(req, dict):
                return None if req is None else self.reply(400, {"error": "bad body"})
            if route == ("PUT", "/pin"):
                if not HEX64.match(str(req.get("verifier"))):
                    return self.reply(400, {"error": "need {verifier: 64 hex}"})
                pins[who] = {"secret": secrets.token_hex(32), "verifier": req["verifier"], "fails": 0}
                print(f"[{who}] PIN set", flush=True)
                return self.reply(200, {"secret": pins[who]["secret"]})
            if not HEX64.match(str(req.get("proof"))):
                return self.reply(400, {"error": "need {proof: 64 hex}"})
            rec = pins.get(who)
            if not rec:
                return self.reply(404, {"error": "no PIN set"})
            if hmac.compare_digest(hashlib.sha256(req["proof"].encode()).hexdigest(), rec["verifier"]):
                rec["fails"] = 0
                return self.reply(200, {"secret": rec["secret"]})
            rec["fails"] += 1
            if rec["fails"] >= PIN_TRIES:
                del pins[who]
                print(f"[{who}] wrong PIN, PIN removed", flush=True)
                return self.reply(410, {"error": "too many wrong PINs; the PIN was removed", "left": 0})
            return self.reply(403, {"error": "wrong PIN", "left": PIN_TRIES - rec["fails"]})
        if route == ("GET", "/entries"):
            after = int(parse_qs(url.query).get("after", ["0"])[0])
            return self.reply(200, {"entries": [e for e in state["entries"].values() if e["seq"] > after],
                                    "seq": state["seq"]})
        if route in (("PUT", "/meta"), ("POST", "/entries"), ("POST", "/access")):
            req = self.body()
            if not isinstance(req, dict):
                return None if req is None else self.reply(400, {"error": "bad body"})
            if route == ("PUT", "/meta"):
                current = state["meta"]["rev"] if state["meta"] else 0
                if req.get("if_rev") != current:
                    return self.reply(409, {"error": "rev changed"})
                state["meta"] = req["meta"]
                print(f"[{who}] vault key updated (rev {req['meta']['rev']})", flush=True)
                return self.reply(200, {"ok": True})
            if route == ("POST", "/entries"):
                entries = req.get("entries")
                if not isinstance(entries, list) or len(entries) > MAX_BATCH or not all(
                        isinstance(e, dict) and ID.match(str(e.get("id"))) and isinstance(e.get("updated"), int)
                        and isinstance(e.get("deleted"), bool) and isinstance(e.get("alg"), str)
                        and isinstance(e.get("data"), str) for e in entries):
                    return self.reply(400, {"error": "bad entry record"})
                accepted = 0
                for e in entries:
                    cur = state["entries"].get(e["id"])
                    if cur and not newer(e, cur):
                        continue
                    state["seq"] += 1
                    state["entries"][e["id"]] = dict(e, seq=state["seq"])
                    accepted += 1
                if accepted:
                    print(f"[{who}] synced {accepted} change(s)", flush=True)
                return self.reply(200, {"seq": state["seq"]})
            print(f"[{who}] wants: {req.get('platform')}  user: {req.get('username')}", flush=True)  # the OLED
            return self.reply(200, {"ok": True})
        return self.reply(404, {"error": "not found"})

    def do_GET(self):
        with lock:
            self.handle_request("GET")

    def do_PUT(self):
        with lock:
            self.handle_request("PUT")

    def do_POST(self):
        with lock:
            self.handle_request("POST")

    def do_DELETE(self):
        with lock:
            self.handle_request("DELETE")


class PairHandler(Handler):
    """The pairing port: no client cert. Unlike the board it stays open after a request."""

    def setup(self):
        self.request = ctx_holder["pair_ctx"].wrap_socket(self.request, server_side=True)
        BaseHTTPRequestHandler.setup(self)

    def do_POST(self):
        with lock:
            if self.path != "/pair":
                return self.reply(404, {"error": "not found"})
            req = self.body()
            if not isinstance(req, dict):
                return None if req is None else self.reply(400, {"error": "bad body"})
            name, csr = str(req.get("name", "")), str(req.get("csr", ""))
            want = mac(f"pwvault-pair-req\n{pairing['server_fp']}\n{name}\n{csr}")
            if not hmac.compare_digest(want, str(req.get("mac", ""))):
                return self.reply(403, {"error": "wrong code (or someone is intercepting)"})
            if not NAME.match(name):
                return self.reply(400, {"error": "name: 1-20 chars of a-z 0-9 -"})
            try:
                cert = sign(name, base64.b64decode(csr))
            except (ValueError, subprocess.CalledProcessError):
                return self.reply(400, {"error": "bad csr"})
            devices[name] = hashlib.sha256(cert).hexdigest()
            pins.pop(name, None)  # a PIN belongs to the old pairing
            print(f"[{name}] paired", flush=True)
            cert_b64 = base64.b64encode(cert).decode()
            return self.reply(200, {"cert": cert_b64,
                                    "mac": mac(f"pwvault-pair-resp\n{pairing['server_fp']}\n{cert_b64}")})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--pair-port", type=int, help="default: --port + 1")
    ap.add_argument("--ca-dir", required=True, help="the fake board's device CA (created if missing)")
    ap.add_argument("--code", help="pairing code (16 chars); default: random, printed")
    a = ap.parse_args()
    make_ca(a.ca_dir)
    alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    pairing.update(code=a.code or "".join(secrets.choice(alpha) for _ in range(16)), ca_dir=a.ca_dir,
                   server_fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(a.cert).read())).hexdigest())
    pair_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pair_ctx.load_cert_chain(a.cert, a.key)
    ctx_holder["pair_ctx"] = pair_ctx
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.load_verify_locations(f"{a.ca_dir}/ca.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED  # no device certificate, no handshake
    # Threaded: clients keep connections open (keep-alive), and the board serves several sockets at once too.
    # The handshake runs per connection in its thread, so a client without a certificate can't stall the others.
    ctx_holder["ctx"] = ctx
    server = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    server.daemon_threads = True
    pair_port = a.pair_port or a.port + 1
    pair_server = ThreadingHTTPServer(("127.0.0.1", pair_port), PairHandler)
    pair_server.daemon_threads = True
    threading.Thread(target=pair_server.serve_forever, daemon=True).start()
    print(f"fake ESP32 on 127.0.0.1:{a.port}, pairing on :{pair_port} with code {pairing['code']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
