#!/usr/bin/env python3
"""`password_manager --serve` with the repo's own clients (docs/PROTOCOL.md §6-10), what api_test.py can't show:
esp32/pki.sh pairing with it, the C++ client's full round trip through it (vault_test), the storage it reports
before there's a vault, and standing down for a dedicated host of the same vault (§6, one active host per network).

  nix-shell -p openssl curl python3 --run 'python3 tests/serve_test.py'   # repo root, after a build
"""
import json
import subprocess
import tempfile
import threading

from harness import APP, ROOT, Checks, Proc, fake_host, sandbox, serve_host

PORT, FAKE_CODE = 18643, "ABCD0123EFGH4567"


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
    c = Checks("serve_test")
    tmp = tempfile.mkdtemp(prefix="serve_test_")
    host_env = sandbox(tmp, "host")
    client_env = sandbox(tmp, "client", espHost="127.0.0.1", espPort=str(PORT))

    def with_pki():
        host = serve_host(host_env, PORT)
        host.type("p")
        code = host.expect(r"Code (\w{4}-\w{4}-\w{4}-\w{4})").group(1)
        result = {}
        t = threading.Thread(target=lambda: result.update(r=pair(client_env, "laptop", PORT + 1, code)))
        t.start()
        host.expect(r"Pair 'laptop' with this host\?")
        host.type("y")
        t.join()
        c.check(result["r"].returncode == 0 and "paired as 'laptop'" in result["r"].stdout,
                "esp32/pki.sh pairs with it, approved at the host", result["r"].stdout + result["r"].stderr)
        status, body = curl(client_env, "GET", "/devices")
        st = json.loads(body)["storage"]  # no vault.json yet: nothing used, and real disk space, not a wraparound
        c.check(status == 200 and st["used"] == 0 and st["records"] == 0 and 0 < st["total"] < 2**60,
                "storage on a host with no vault yet", st)
        cfg = f"{client_env['XDG_CONFIG_HOME']}/pwvault"
        r = subprocess.run([f"{ROOT}/vault_test"], env=dict(client_env, PWVAULT_TEST_ESP=f"127.0.0.1:{PORT},"
                           f"{cfg}/server.pem,{cfg}/device.pem,{cfg}/device.key"), capture_output=True, text=True)
        c.check(r.returncode == 0 and "41 records round-tripped" in r.stdout,
                "the C++ client's round trip through it (vault_test)", r.stdout[-400:] + r.stderr[-400:])
        host.stop()

    def standing_down():
        fake = fake_host(tmp, "board", PORT + 10, FAKE_CODE)
        conf = f"{host_env['XDG_CONFIG_HOME']}/pwvault/config"
        kept = [line for line in open(conf) if not line.startswith(("espHost=", "espPort="))]
        open(conf, "w").write("".join(kept) + f"espHost=127.0.0.1\nespPort={PORT + 10}\n")
        c.check(pair(host_env, "pi", PORT + 11, FAKE_CODE).returncode == 0, "the host pairs with a board as a client")
        host = Proc([APP, "--serve", "--port", str(PORT), "--role", "server"], host_env)
        c.check(host.saw(r"Standing down: 127\.0\.0\.1:%d hosts this vault here" % (PORT + 10), 20) is not None,
                "with a dedicated host of the same vault answering, it stands down")
        c.equal(curl(client_env, "GET", "/meta")[0], 0, "...and doesn't listen")
        host.stop()
        fake.stop()

    c.run("pki.sh, storage, the C++ client", with_pki)
    c.run("one active host per network (§6)", standing_down)
    c.done()


if __name__ == "__main__":
    main()
