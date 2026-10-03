#!/usr/bin/env python3
"""End-to-end test of `password_manager --serve` (docs/PROTOCOL.md §6-10), driven through its terminal like a person
at the host. Everything runs in temp dirs (XDG_CONFIG_HOME/XDG_DATA_HOME); nothing touches the real board.

  nix-shell -p openssl curl python3 --run 'python3 tests/serve_test.py'   # from the repo root, after a build

Checks: pairing approved at the host (pki.sh), vault_test's full round trip against it, a wrong code closing
pairing, a revoke that only happens once approved there, and standing down for a dedicated host of the same vault
(tests/fake_esp.py).
"""
import atexit
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 18643
children = []  # killed on any exit: a host left running keeps the port, and the next run meets its cert
atexit.register(lambda: [c.kill() for c in children if c.poll() is None])


class Serve:
    """--serve with a pipe for its terminal. Its questions end without a newline, so output is read as it comes."""

    def __init__(self, env, *args):
        self.p = subprocess.Popen([f"{ROOT}/password_manager", "--serve", "--port", str(PORT), *args], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        children.append(self.p)
        self.chunks = queue.Queue()
        self.seen = ""  # output not yet matched
        threading.Thread(target=lambda: [self.chunks.put(c) for c in iter(lambda: os.read(self.p.stdout.fileno(),
                         4096), b"")], daemon=True).start()

    def type(self, line):
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()

    def wait_for(self, pattern, seconds=20):
        until = time.time() + seconds
        while time.time() < until:
            if m := re.search(pattern, self.seen):
                self.seen = self.seen[m.end():]
                return m
            try:
                self.seen += re.sub(r"\x1b\[[0-9;]*m", "", self.chunks.get(timeout=0.2).decode(errors="replace"))
            except queue.Empty:
                pass
        sys.exit(f"FAIL: no output matching {pattern!r}; got {self.seen[-500:]!r}")

    def quit(self):
        self.type("q")
        self.p.wait(10)


def check(ok, what):
    print(("ok  " if ok else "FAIL ") + what, flush=True)
    if not ok:
        sys.exit(1)


def sandbox(tmp, name, host_port=None):
    env = dict(os.environ, XDG_CONFIG_HOME=f"{tmp}/{name}/cfg", XDG_DATA_HOME=f"{tmp}/{name}/data")
    os.makedirs(f"{tmp}/{name}/cfg/pwvault")
    if host_port:
        open(f"{tmp}/{name}/cfg/pwvault/config", "w").write(f"espHost=127.0.0.1\nespPort={host_port}\n")
    return env


def pair(env, name, pair_port, code):
    return subprocess.run([f"{ROOT}/esp32/pki.sh", "pair", name], env=dict(env, PWVAULT_PAIR_PORT=str(pair_port),
                          PWVAULT_CODE=code), capture_output=True, text=True)


def curl(env, method, path, port=PORT):
    c = f"{env['XDG_CONFIG_HOME']}/pwvault"
    r = subprocess.run(["curl", "-s", "-w", "\n%{http_code}", "-X", method, "--cacert", f"{c}/server.pem", "--cert",
                        f"{c}/device.pem", "--key", f"{c}/device.key", "--resolve", f"pwvault.local:{port}:127.0.0.1",
                        f"https://pwvault.local:{port}{path}"], capture_output=True, text=True)
    body, _, status = r.stdout.rpartition("\n")
    return int(status or 0), body


def main():
    tmp = tempfile.mkdtemp(prefix="serve_test_")
    host_env, client_env = sandbox(tmp, "host"), sandbox(tmp, "client", PORT)

    host = Serve(host_env, "--role", "server")
    host.wait_for(r"Serving .* as a server host")
    host.type("p")
    code = host.wait_for(r"Code (\w{4}-\w{4}-\w{4}-\w{4})").group(1)
    result = {}
    t = threading.Thread(target=lambda: result.update(r=pair(client_env, "laptop", PORT + 1, code)))
    t.start()
    host.wait_for(r"Pair 'laptop' with this host\?")
    host.type("y")
    t.join()
    check(result["r"].returncode == 0 and "paired as 'laptop'" in result["r"].stdout, "pairing, approved at the host")
    status, body = curl(client_env, "GET", "/devices")
    info = json.loads(body)
    check(status == 200 and info["you"] == "laptop" and info["role"] == "server", "GET /devices: you, role")
    st = info["storage"]  # no vault.json yet: nothing used, and a total that's real disk space, not a wraparound
    check(st["used"] == 0 and st["records"] == 0 and 0 < st["total"] < 2**60, "storage on a new host")
    check(curl(client_env, "PUT", "/pin")[0] == 404, "no PIN on a server host (§11)")

    c = f"{client_env['XDG_CONFIG_HOME']}/pwvault"
    r = subprocess.run([f"{ROOT}/vault_test"], env=dict(client_env, PWVAULT_TEST_ESP=f"127.0.0.1:{PORT},{c}/server.pem,"
                       f"{c}/device.pem,{c}/device.key"), capture_output=True, text=True)
    check(r.returncode == 0 and "41 records round-tripped" in r.stdout, "vault_test's round trip through the host")

    host.type("p")
    code = host.wait_for(r"Code (\w{4}-\w{4}-\w{4}-\w{4})").group(1)
    other = sandbox(tmp, "other", PORT)
    wrong = "0" * 16 if code.replace("-", "") != "0" * 16 else "1" * 16
    check(pair(other, "mallory", PORT + 1, wrong).returncode != 0, "a wrong code is refused")
    host.wait_for(r"wrong code. Pairing is closed")
    check(pair(other, "mallory", PORT + 1, code).returncode != 0, "...and closes pairing, even for the right code")

    check(curl(client_env, "DELETE", "/devices/laptop")[0] == 202, "DELETE /devices: only a request (202)")
    host.wait_for(r"Revoke 'laptop' \(asked by laptop\)\?")
    check(curl(client_env, "GET", "/meta")[0] in (200, 404), "...still allowed until approved")
    host.type("y")
    host.wait_for(r"\[laptop\] revoked")
    status, body = curl(client_env, "GET", "/meta")
    check(status == 403 and "device revoked" in body, "revoked once approved at the host: 403")
    host.quit()

    # One active host per network: with a dedicated host of the same vault answering, a server host stands down
    fake_dir = f"{tmp}/fake"
    os.makedirs(fake_dir)
    fake = subprocess.Popen([sys.executable, f"{ROOT}/tests/fake_esp.py", "--port", str(PORT + 10), "--cert",
                             f"{ROOT}/esp32/vault/cert.pem", "--key", f"{ROOT}/esp32/vault/key.pem", "--ca-dir",
                             fake_dir, "--code", "ABCD0123EFGH4567"], stdout=subprocess.DEVNULL)
    children.append(fake)
    time.sleep(2)
    conf = f"{host_env['XDG_CONFIG_HOME']}/pwvault/config"
    kept = [l for l in open(conf) if not l.startswith(("espHost=", "espPort="))]
    open(conf, "w").write("".join(kept) + f"espHost=127.0.0.1\nespPort={PORT + 10}\n")
    check(pair(host_env, "pi", PORT + 11, "ABCD0123EFGH4567").returncode == 0, "the host pairs with a board as a client")
    host = Serve(host_env, "--role", "server")
    host.wait_for(r"Standing down: 127.0.0.1:%d hosts this vault here" % (PORT + 10))
    check(curl(client_env, "GET", "/meta")[0] == 0, "...and doesn't listen")
    host.quit()
    fake.terminate()
    print("all serve tests passed")


if __name__ == "__main__":
    main()
