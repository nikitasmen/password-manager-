#!/usr/bin/env python3
"""The host API over the wire (docs/PROTOCOL.md §7-11): conformance and security, with no app code in between.

Raw HTTPS with mutual TLS, pairing done by hand (CSR, macs). Every block runs against both hosts in the repo:
tests/fake_esp.py (dedicated, the board's stand-in that the other suites trust) and `password_manager --serve`
(server), so both are held to the same contract. Where the fake differs on purpose (pairing always open, approval
automatic), the check says so instead of skipping silently.

  nix-shell -p openssl curl python3 --run 'python3 tests/api_test.py'   # repo root, after a build
"""
import base64
import hashlib
import hmac
import http.client
import json
import socket
import ssl
import tempfile
import threading

from harness import Checks, fake_host, openssl, sandbox, serve_host

FAKE_CODE = "ABCD0123EFGH4567"
NOTHING = (OSError, ssl.SSLError, http.client.HTTPException)  # what a refused handshake looks like to a client


class Conn(http.client.HTTPSConnection):
    """HTTPS to 127.0.0.1, verified as pwvault.local against the pinned host cert (§7), like every client."""

    def __init__(self, port, server_pem, cert=None, key=None):
        ctx = ssl.create_default_context(cafile=server_pem)
        if cert:
            ctx.load_cert_chain(cert, key)
        super().__init__("pwvault.local", port, context=ctx, timeout=90)

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname="pwvault.local")

    def call(self, method, path, body=None, raw=None):
        data = raw if raw is not None else None if body is None else json.dumps(body).encode()
        self.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
        r = self.getresponse()
        text = r.read()
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, None


class Device:
    """A paired client: its cert and key, and a fresh connection per call."""

    def __init__(self, host, name, cert, key):
        self.host, self.name, self.cert, self.key = host, name, cert, key

    def call(self, method, path, body=None, raw=None):
        return Conn(self.host.port, self.host.server_pem, self.cert, self.key).call(method, path, body, raw)


class Host:
    """One host under test, and how a person at it opens pairing and approves."""

    def __init__(self, tmp, kind):
        self.tmp, self.kind = tmp, kind
        if kind == "fake":
            self.port, self.role, self.strict_sessions = 19143, "dedicated", False
            self.proc = fake_host(tmp, "fake", self.port, FAKE_CODE)
        else:
            self.port, self.role, self.strict_sessions = 19153, "server", True
            self.proc = serve_host(sandbox(tmp, "serve"), self.port)
        self.server_pem = f"{tmp}/{kind}-pinned.pem"
        pem = ssl.get_server_certificate(("127.0.0.1", self.port + 1))
        open(self.server_pem, "w").write(pem)
        self.fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()  # what pairing binds the macs to (§9)
        self.n = 0

    def open_pairing(self):
        if self.kind == "fake":
            return FAKE_CODE  # always open
        self.proc.type("p")
        return self.proc.expect(r"Code (\w{4}-\w{4}-\w{4}-\w{4})").group(1).replace("-", "")

    def approving(self, question, fn):
        """Runs fn (a request that may wait for someone at the host); answers y if the host asks `question`."""
        if self.kind == "fake":
            return fn()
        out = {}
        t = threading.Thread(target=lambda: out.update(r=fn()))
        t.start()
        asked = self.proc.saw(question, seconds=5)
        if asked:
            self.proc.type("y")
        t.join(90)
        return out["r"]

    def pair(self, name, code, fp=None, csr=None, approve=True):
        """§9 by hand. Returns (status, body, key path, csr base64)."""
        self.n += 1
        key = f"{self.tmp}/{self.kind}-{name}-{self.n}.key"
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        csr_b64 = csr or base64.b64encode(openssl("req", "-new", "-key", key, "-subj", f"/CN={name}",
                                                  "-outform", "DER")).decode()
        mac = hmac.new(code.encode(), f"pwvault-pair-req\n{fp or self.fp}\n{name}\n{csr_b64}".encode(),
                       hashlib.sha256).hexdigest()
        post = lambda: Conn(self.port + 1, self.server_pem).call("POST", "/pair",  # noqa: E731
                                                                 {"name": name, "csr": csr_b64, "mac": mac})
        status, body = self.approving(rf"Pair '{name}'", post) if approve else post()
        return status, body, key, csr_b64

    def device(self, name, body, key):
        cert = f"{self.tmp}/{self.kind}-{name}-{self.n}.pem"
        open(cert, "w").write(ssl.DER_cert_to_PEM_cert(base64.b64decode(body["cert"])))
        return Device(self, name, cert, key)


def response_mac(code, fp, cert_b64):
    return hmac.new(code.encode(), f"pwvault-pair-resp\n{fp}\n{cert_b64}".encode(), hashlib.sha256).hexdigest()


def record(i, updated=1000, data="AAAA", deleted=False):
    return {"id": f"{i:032x}", "updated": updated, "deleted": deleted, "alg": "aes-256-gcm", "data": data}


def meta(rev, key="KEY"):
    return {"v": 1, "vault_id": "0" * 32, "rev": rev, "kdf": "pbkdf2-sha256", "iter": 1000, "salt": "c2FsdA==",
            "alg": "aes-256-gcm", "key": f"{key}{rev}"}


def suite(c, h):
    s = {}  # what later blocks need: the paired devices

    def pairing():
        code = h.open_pairing()
        status, body, key, _ = h.pair("alice", code)
        c.equal(status, 200, "pair: a request with the right code is accepted")
        c.equal(body.get("mac"), response_mac(code, h.fp, body.get("cert", "")),
                "pair: the reply is signed with the code, bound to the host's cert")
        alice = s["alice"] = h.device("alice", body, key)
        subject = openssl("x509", "-in", alice.cert, "-noout", "-subject", "-issuer", "-nameopt", "RFC2253").decode()
        c.check("subject=CN=alice" in subject, "pair: the cert names the device (CN)", subject)
        c.check("issuer=CN=pwvault device CA" in subject, "pair: issued by the host's device CA", subject)
        ext = openssl("x509", "-in", alice.cert, "-noout", "-ext", "extendedKeyUsage,keyUsage").decode()
        c.check("TLS Web Client Authentication" in ext and "Digital Signature" in ext,
                "pair: client auth only (EKU clientAuth, keyUsage digitalSignature)", ext)
        c.equal(openssl("x509", "-in", alice.cert, "-noout", "-pubkey"), openssl("pkey", "-in", key, "-pubout"),
                "pair: the cert is for the key in our CSR, not one the host chose")

    def transport():
        c.equal(s["alice"].call("GET", "/nothing-here")[0], 404, "an unknown path is 404")
        try:
            Conn(h.port, h.server_pem).call("GET", "/meta")
            refused = False
        except NOTHING:
            refused = True
        c.check(refused, "TLS: no client cert, no answer (§7)")
        foreign_key, foreign = f"{h.tmp}/{h.kind}-foreign.key", f"{h.tmp}/{h.kind}-foreign.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                "-subj", "/CN=alice", "-keyout", foreign_key, "-out", foreign)
        try:
            Conn(h.port, h.server_pem, foreign, foreign_key).call("GET", "/meta")
            refused = False
        except NOTHING:
            refused = True
        c.check(refused, "TLS: a self-made cert with a paired device's name is refused")

    def metas():
        a = s["alice"]
        c.equal(a.call("GET", "/meta")[0], 404, "GET /meta: 404 before there's a vault")
        c.equal(a.call("PUT", "/meta", {"meta": meta(1), "if_rev": 0}), (200, {"ok": True}), "PUT /meta: the first")
        c.equal(a.call("GET", "/meta"), (200, meta(1)), "GET /meta: verbatim, as stored")
        c.equal(a.call("PUT", "/meta", {"meta": meta(1, "OTHER"), "if_rev": 0})[0], 409,
                "PUT /meta: compare-and-swap refuses a stale if_rev")
        c.equal(a.call("GET", "/meta"), (200, meta(1)), "...and the stored meta is unchanged")
        c.equal(a.call("PUT", "/meta", {"meta": meta(2), "if_rev": 1})[0], 200, "PUT /meta: the next rev")
        c.equal(a.call("PUT", "/meta", {"if_rev": 2})[0], 400, "PUT /meta without a meta: 400")
        c.equal(a.call("PUT", "/meta", raw=b"not json")[0], 400, "PUT /meta with a body that isn't JSON: 400")
        c.equal(a.call("GET", "/meta"), (200, meta(2)), "...and neither changed it")

    def entries():
        a = s["alice"]
        c.equal(a.call("GET", "/entries?after=0"), (200, {"entries": [], "seq": 0}), "GET /entries: none yet")
        c.equal(a.call("POST", "/entries", {"entries": [record(1), record(2), record(3)]}), (200, {"seq": 3}),
                "POST /entries: each accepted record gets the next seq")
        status, got = a.call("GET", "/entries?after=0")
        c.check(status == 200 and got["seq"] == 3 and sorted(e["seq"] for e in got["entries"]) == [1, 2, 3],
                "GET /entries?after=0: all of them, seq 1-3", got)
        c.check(all({k: e[k] for k in ("id", "updated", "deleted", "alg", "data")} == record(int(e["id"], 16))
                    for e in got["entries"]), "...exactly as sent")
        c.equal(a.call("GET", "/entries?after=3"), (200, {"entries": [], "seq": 3}), "after=3: nothing newer")
        c.equal(len(a.call("GET", "/entries?after=1")[1]["entries"]), 2, "after=1: the two newer")

        # §5 on the host: last writer wins on (updated, data); a tombstone loses a tie
        c.equal(a.call("POST", "/entries", {"entries": [record(1, updated=999, data="ZZZZ")]})[1], {"seq": 3},
                "merge: an older record is ignored (no new seq)")
        c.equal(a.call("POST", "/entries", {"entries": [record(1, data="AAAB")]})[1], {"seq": 4},
                "merge: the same time with bytewise larger data wins")
        c.equal(a.call("POST", "/entries", {"entries": [record(1, data="", deleted=True)]})[1], {"seq": 4},
                "merge: a tombstone loses a tie")
        c.equal(a.call("POST", "/entries", {"entries": [record(1, updated=1001, data="", deleted=True)]})[1],
                {"seq": 5}, "merge: a newer tombstone deletes")
        newest = {e["id"]: e for e in a.call("GET", "/entries?after=0")[1]["entries"]}[f"{1:032x}"]
        c.check(newest["deleted"] is True and newest["seq"] == 5, "...and is what the host keeps", newest)

        # validation: the whole batch is refused, nothing is written (§7)
        bad = {
            "an uppercase id": dict(record(9), id="A" * 32),
            "a 31-character id": dict(record(9), id="a" * 31),
            "a path as id": dict(record(9), id="../../../../../../etc/passwd"),
            "an id with a trailing newline": dict(record(9), id="a" * 32 + "\n"),
            "updated as a string": dict(record(9), updated="1000"),
            "updated as a fraction": dict(record(9), updated=1000.5),
            "updated as a boolean": dict(record(9), updated=True),
            "deleted as a string": dict(record(9), deleted="false"),
            "no alg": {k: v for k, v in record(9).items() if k != "alg"},
            "data as a number": dict(record(9), data=7),
        }
        for what, r in bad.items():
            c.equal(a.call("POST", "/entries", {"entries": [record(8), r]})[0], 400, f"POST /entries with {what}: 400")
        c.equal(a.call("POST", "/entries", {"entries": [record(100 + i) for i in range(33)]})[0], 400,
                "POST /entries with 33 records (more than 32): 400")
        c.equal(a.call("POST", "/entries", {"entries": "nope"})[0], 400, "POST /entries where entries isn't a list")
        c.equal(a.call("GET", "/entries?after=0")[1]["seq"], 5, "...and none of those wrote anything")
        c.equal(a.call("POST", "/entries", raw=json.dumps({"entries": [], "pad": "x" * 17000}).encode())[0], 413,
                "a body over 16 KB: 413")
        status, _ = a.call("GET", "/entries?after=nope")  # the board reads it as 0, --serve refuses it: both fine
        c.check(status < 500, "GET /entries?after=nope: an answer, not a crash", status)
        c.equal(a.call("GET", "/entries?after=0")[1]["seq"], 5, "...and the host still answers")

    def devices():
        a = s["alice"]
        c.equal(a.call("POST", "/access", {"platform": "GitHub", "username": "nik"}), (200, {"ok": True}),
                "POST /access: a display-only hint")
        status, d = a.call("GET", "/devices")
        c.equal(status, 200, "GET /devices")
        c.equal(d.get("you"), "alice", "GET /devices: you is the cert's name")
        c.equal(d.get("role"), h.role, "GET /devices: the host's role (§6)")
        c.check([x["name"] for x in d.get("devices", [])] == ["alice"] and isinstance(d["devices"][0]["seen"], int),
                "GET /devices: the paired names, with seen times", d)
        st = d.get("storage", {})
        c.check(all(isinstance(st.get(k), int) for k in ("used", "total", "records")) and 0 < st["used"] <= st["total"]
                and st["records"] == 3, "GET /devices: storage (bytes used <= total, 3 records)", st)
        status, inv = a.call("POST", "/pair/open")
        c.check(status == 200 and len(inv["code"]) == 16 and inv["qr"].startswith("PWVAULT:")
                and inv["qr"].split(":")[2] == inv["code"] and 0 < inv["seconds"] <= 120,
                "POST /pair/open: the code, its QR text (§9) and the time left", inv)

    def pins():
        a = s["alice"]
        proof, wrong = "a" * 64, "b" * 64
        verifier = hashlib.sha256(proof.encode()).hexdigest()
        if h.role != "dedicated":
            c.equal(a.call("PUT", "/pin", {"verifier": verifier})[0], 404,
                    "PUT /pin: 404 on a host that isn't dedicated")
            c.equal(a.call("POST", "/pin", {"proof": proof})[0], 404, "POST /pin: 404 there too")
            return
        c.equal(a.call("PUT", "/pin", {"verifier": "short"})[0], 400, "PUT /pin with a malformed verifier: 400")
        status, body = a.call("PUT", "/pin", {"verifier": verifier})
        secret = body.get("secret", "") if body else ""
        c.check(status == 200 and len(secret) == 64 and int(secret, 16) >= 0, "PUT /pin: a 64-hex secret", body)
        c.equal(a.call("POST", "/pin", {"proof": proof}), (200, {"secret": secret}), "POST /pin: the right proof")
        lefts = [a.call("POST", "/pin", {"proof": wrong}) for _ in range(4)]
        c.equal([(st, b.get("left")) for st, b in lefts], [(403, 4), (403, 3), (403, 2), (403, 1)],
                "POST /pin: wrong proofs count down")
        c.equal(a.call("POST", "/pin", {"proof": proof})[0], 200, "...and the right one resets the count")
        results = [a.call("POST", "/pin", {"proof": wrong})[0] for _ in range(5)]
        c.equal(results, [403, 403, 403, 403, 410], "the 5th wrong proof removes the PIN (410)")
        c.equal(a.call("POST", "/pin", {"proof": proof})[0], 404, "...after which even the right one finds nothing")

    def pairing_attacks():
        code = h.open_pairing()
        c.equal(h.pair("mallory", "0" * 16 if code != "0" * 16 else "1" * 16, approve=False)[0], 403,
                "pair: a wrong code is refused (403)")
        if h.strict_sessions:
            c.equal(h.pair("mallory", code, approve=False)[0], 403,
                    "pair: ...and closes pairing, even for the right code (one request per session)")
        else:
            print("      (the fake keeps pairing open after a wrong code; the board and --serve don't)")
        code = h.open_pairing()
        c.equal(h.pair("mallory", code, fp="f" * 64, approve=False)[0], 403,
                "pair: a mac bound to another server cert (a man in the middle) is refused")
        code = h.open_pairing()
        c.equal(h.pair("Mallory!", code, approve=False)[0], 400, "pair: a name outside a-z 0-9 - is refused")
        code = h.open_pairing()
        c.equal(h.pair("mallory\n", code, approve=False)[0], 400, "pair: a name with a trailing newline is refused")
        code = h.open_pairing()
        c.equal(h.pair("mallory", code, csr=base64.b64encode(b"not a csr").decode())[0], 400,
                "pair: a CSR that isn't one is refused")
        code = h.open_pairing()
        status, body, key, _ = h.pair("bob", code)
        c.equal(status, 200, "pair: a second device")
        s["bob"] = h.device("bob", body, key)
        if h.strict_sessions:
            c.equal(h.pair("eve", code, approve=False)[0], 403, "pair: the used code can't pair another device")

    def revocation():
        alice, bob = s["alice"], s["bob"]
        c.equal(bob.call("DELETE", "/devices/nobody")[0], 404, "DELETE /devices/<unknown>: 404")
        if h.kind == "fake":
            c.equal(bob.call("DELETE", "/devices/alice"), (202, {"pending": True}), "DELETE /devices: 202 pending")
        else:
            c.equal(bob.call("DELETE", "/devices/bob"), (202, {"pending": True}), "DELETE /devices: 202 pending")
            h.proc.expect(r"Revoke 'bob' \(asked by bob\)\?")
            c.equal(bob.call("DELETE", "/devices/alice"), (202, {"pending": True}), "...a newer request")
            h.proc.expect(r"Revoke 'alice' \(asked by bob\)\?")  # the pending question, now about alice
            c.check(h.proc.saw(r"Revoke '", 2) is None,
                    "...replaces the pending one (§10): one question, and it names what a y will revoke")
            c.equal(alice.call("GET", "/meta")[0], 200, "...only a request: alice works until approved at the host")
            h.proc.type("y")
            h.proc.expect(r"\[alice\] revoked")
            c.equal(bob.call("GET", "/meta")[0], 200, "...and the replaced request revoked nothing: bob still works")
        status, body = alice.call("GET", "/meta")
        c.equal((status, body), (403, {"error": "device revoked"}), "a revoked device: 403 device revoked")
        names = [x["name"] for x in bob.call("GET", "/devices")[1]["devices"]]
        c.equal(names, ["bob"], "...and it's off the device list")

        # Re-pairing a name replaces its cert: the old one stops working (§9)
        code = h.open_pairing()
        status, body, key, _ = h.pair("bob", code)
        new_bob = h.device("bob", body, key)
        c.equal(new_bob.call("GET", "/meta")[0], 200, "re-pairing bob: the new cert works")
        c.equal(bob.call("GET", "/meta"), (403, {"error": "device revoked"}), "re-pairing bob: the old cert is refused")

    blocks = [("pairing", pairing), ("TLS", transport), ("meta (§3, §7)", metas), ("entries (§5, §7)", entries),
              ("devices, access, pairing invites (§7, §9)", devices), ("PIN (§11)", pins),
              ("pairing attacks (§9)", pairing_attacks), ("revocation (§10)", revocation)]
    for title, fn in blocks:
        c.run(f"{h.kind}: {title}", fn)


def main():
    c = Checks("api_test")
    tmp = tempfile.mkdtemp(prefix="api_test_")
    for kind in ("fake", "serve"):
        h = Host(tmp, kind)
        suite(c, h)
        h.proc.stop()
    c.done()


if __name__ == "__main__":
    main()
