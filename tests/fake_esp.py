#!/usr/bin/env python3
"""A stand-in for the ESP32 store (docs/PROTOCOL.md §6-7), for testing clients without touching the real board.

Same API, mutual TLS, revocation and merge rule as esp32/vault/vault.ino; state is kept in memory.

  python3 tests/fake_esp.py --port 8443 --cert esp32/vault/cert.pem --key esp32/vault/key.pem \
      --ca esp32/pki/ca.pem [--revoke NAME ...]
Clients connect with host 127.0.0.1, port 8443 and their device certificate, exactly as for the board.
"""
import argparse
import json
import os
import re
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "python"))
import vaultproto as vp  # noqa: E402

MAX_BODY, MAX_BATCH = 16 * 1024, 32
ID = re.compile(r"^[0-9a-f]{32}$")
state = {"meta": None, "seq": 0, "entries": {}}
lock = threading.Lock()  # one request at a time touches state, like the board's mutex
revoked = set()


ctx_holder = {}


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
        subject = dict(x[0] for x in self.connection.getpeercert()["subject"])
        return subject.get("commonName")

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
        if who in revoked:
            self.reply(403, {"error": "device revoked"})
            self.close_connection = True
            return
        url = urlparse(self.path)
        route = (method, url.path)
        if route == ("GET", "/meta"):
            return self.reply(200, state["meta"]) if state["meta"] else self.reply(404, {"error": "no vault yet"})
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
                    if cur and not vp.newer(e, cur):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=True, help="device CA: only certificates it signed may connect")
    ap.add_argument("--revoke", action="append", default=[])
    a = ap.parse_args()
    revoked.update(a.revoke)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.load_verify_locations(a.ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # no device certificate, no handshake
    # Threaded: clients keep connections open (keep-alive), and the board serves several sockets at once too.
    # The handshake runs per connection in its thread, so a client without a certificate can't stall the others.
    ctx_holder["ctx"] = ctx
    server = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    server.daemon_threads = True
    print(f"fake ESP32 on 127.0.0.1:{a.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
