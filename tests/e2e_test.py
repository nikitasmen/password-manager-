#!/usr/bin/env python3
"""Business flows through the real app: the terminal UI of sandboxed "devices", driven like a person would, against
a real `password_manager --serve` host and a dedicated fake (tests/fake_esp.py), as separate processes.

Onboarding and joining, edits and deletes reaching the other device, wrong passwords, a master password change, a
host going away and coming back, revoking a device, PIN unlock (dedicated hosts only), an old pairing moving into
hosts/, and what lands on disk (no plaintext on hosts, keys mode 600).

  nix-shell -p openssl curl python3 --run 'python3 tests/e2e_test.py'   # repo root, after a build
"""
import glob
import json
import os
import stat
import subprocess
import tempfile
import time

from harness import APP, ROOT, Checks, Proc, fake_host, sandbox, serve_host

HOST_PORT, FAKE_PORT, FAKE_CODE = 19243, 19253, "ABCD0123EFGH4567"
PW, PW2 = "correct horse 1", "battery staple 2"


class App:
    """`password_manager -t` on one device, driven through its prompts."""

    def __init__(self, env):
        self.p = Proc([APP, "-t"], env)

    def create(self, pw):
        self.p.expect(r"Master password: ")
        self.p.type(pw)
        self.p.expect(r"Repeat it: ")
        self.p.type(pw)
        self.home()

    def unlock(self, pw):
        self.p.expect(r"Master password: ")
        self.p.type(pw)
        self.home()

    def home(self):
        return self.p.expect(r"(\d+ entr(?:y|ies))[\s\S]*?\n([^\n]*q quit)")  # the header, then the commands

    def entries(self):
        self.p.type("")  # an empty line redraws the list
        m = self.home()
        return m.group(1)

    def add(self, platform, user, pw):
        self.p.type("n")
        for prompt, text in ((r"Website or app: ", platform), (r"Username: ", user), (r"Password: ", pw),
                             (r"Repeat password: ", pw)):
            self.p.expect(prompt)
            self.p.type(text)
        self.p.expect(r"Encryption")
        self.p.type("")  # the default cipher
        self.p.expect(r"Enter back")
        self.p.type("")
        self.home()

    def password_of(self, platform):
        """Opens the entry, shows its password, and goes back."""
        self.p.type(platform)
        m = self.p.saw(r"Enter back", 10)
        if not m:
            self.home()
            return None
        self.p.type("s")
        pw = self.p.expect(r"Password\s+(\S[^\n]*?)\s*\n").group(1)
        self.p.expect(r"Enter back")
        self.p.type("")
        self.home()
        return pw

    def edit_password(self, platform, pw):
        self.p.type(platform)
        self.p.expect(r"Enter back")
        self.p.type("e")
        self.p.expect(r"Username .*: ")
        self.p.type("")
        self.p.expect(r"New password: ")
        self.p.type(pw)
        self.p.expect(r"Repeat it: ")
        self.p.type(pw)
        self.p.expect(r"Encryption")
        self.p.type("")
        self.p.expect(r"Enter back")
        self.p.type("")
        self.home()

    def delete(self, platform):
        self.p.type(platform)
        self.p.expect(r"Enter back")
        self.p.type("d")
        self.p.expect(r"\[y/N\]")
        self.p.type("y")
        self.home()

    def change_master(self, old, new):
        self.p.type("p")
        for prompt, text in ((r"Current master password: ", old), (r"New master password: ", new),
                             (r"Repeat the new one: ", new)):
            self.p.expect(prompt)
            self.p.type(text)
        self.p.expect(r"Master password changed")

    def pair_from_hosts(self, host, address, name, code_of):
        """Devices -> a: pairs with a host whose code `code_of()` reads, approving at the host if it asks."""
        self.p.type("d")
        self.p.expect(r"add a host")
        self.p.type("a")
        self.answer_pairing(host, address, name, code_of)
        self.p.expect(r"Paired with " + address.replace(".", r"\."))
        self.p.type("")  # back to the vault
        self.home()

    def answer_pairing(self, host, address, name, code_of):
        self.p.expect(r"Host address .*: ")
        self.p.type(address)
        self.p.expect(r"Name for this computer .*: ")
        self.p.type(name)
        self.p.expect(r"Code on the host: ")
        self.p.type(code_of())
        if host:
            host.expect(rf"Pair '{name}' with this host\?")
            host.type("y")

    def quit(self):
        self.p.type("q")
        self.p.p.wait(15)


def serve_code(host):
    host.type("p")
    return host.expect(r"Code (\w{4}-\w{4}-\w{4}-\w{4})").group(1)


def plaintext_in(path, secrets):
    raw = open(path, encoding="utf-8", errors="replace").read() if os.path.exists(path) else ""
    return [s for s in secrets if s in raw]


def main():
    c = Checks("e2e_test")
    tmp = tempfile.mkdtemp(prefix="e2e_test_")
    host_env = sandbox(tmp, "host")
    host_vault = f"{tmp}/host/data/pwvault/vault.json"
    address = f"127.0.0.1:{HOST_PORT}"
    a_env = sandbox(tmp, "a")
    b_env = sandbox(tmp, "b", espHost=address)  # joins through the connector, like a new computer would
    state = {"host": serve_host(host_env, HOST_PORT)}

    def onboarding():
        a = App(a_env)
        a.create(PW)
        a.pair_from_hosts(state["host"], address, "a-laptop", lambda: serve_code(state["host"]))
        a.add("GitHub", "nik@example.com", "gh-s3cret-1")
        a.add("Bank", "nik", "b4nk-s3cret")
        c.equal(a.entries(), "2 entries", "A: two entries")
        a.quit()
        c.equal(plaintext_in(host_vault, ["GitHub", "nik@example.com", "gh-s3cret-1", "Bank", "b4nk-s3cret", PW]), [],
                "the host's vault.json has no platform, username, password or master password in it")
        c.check(os.path.getsize(host_vault) > 0, "...and it isn't empty: the entries are there, encrypted")

        b = App(b_env)
        b.p.expect(r"isn't paired with the host at " + address.replace(".", r"\."))
        b.p.type("p")
        b.answer_pairing(state["host"], "", "b-desk", lambda: serve_code(state["host"]))
        b.unlock(PW)  # the vault came from the host: there was nothing to create
        c.equal(b.entries(), "2 entries", "B joins: the connector pairs it, and A's entries arrive")
        c.equal(b.password_of("GitHub"), "gh-s3cret-1", "B reads A's password")
        b.quit()

    def edits():
        b = App(b_env)
        b.unlock(PW)
        b.edit_password("GitHub", "gh-s3cret-2")
        b.quit()
        a = App(a_env)
        a.unlock(PW)
        c.equal(a.password_of("GitHub"), "gh-s3cret-2", "an edit on B reaches A")
        a.delete("Bank")
        c.equal(a.entries(), "1 entry", "A deletes Bank")
        a.quit()
        b = App(b_env)
        b.unlock(PW)
        c.equal(b.entries(), "1 entry", "the delete reaches B")
        c.equal(b.password_of("Bank"), None, "Bank is gone on B too")
        b.quit()

    def wrong_password():
        a = App(a_env)
        for _ in range(3):
            a.p.expect(r"Master password: ")
            a.p.type("not it")
        a.p.expect(r"Too many wrong passwords")
        a.p.p.wait(15)
        c.check(a.p.p.returncode is not None, "three wrong master passwords: locked out, the app exits")

    def master_password():
        a = App(a_env)
        a.unlock(PW)
        a.change_master(PW, PW2)
        a.quit()
        b = App(b_env)
        b.p.expect(r"Master password: ")
        b.p.type(PW)
        c.check(b.p.saw(r"Master password: ", 30) is not None, "after the change, B refuses the old master password")
        b.p.type(PW2)
        b.home()
        c.equal(b.password_of("GitHub"), "gh-s3cret-2", "...and opens with the new one, entries intact")
        b.quit()

    def offline():
        state["host"].stop()
        a = App(a_env)
        a.unlock(PW2)
        c.check("Hosts offline, working on this computer's copy" in a.p.log,
                "with the host away, A opens its own copy and says so")
        a.add("Offline", "me", "written-offline")
        c.equal(a.password_of("Offline"), "written-offline", "A writes while the host is away")
        a.quit()
        state["host"] = serve_host(host_env, HOST_PORT)  # same identity: the pairings stay valid
        a = App(a_env)
        a.unlock(PW2)  # syncs on unlock: what was written offline goes up
        a.quit()
        b = App(b_env)
        b.unlock(PW2)
        c.equal(b.password_of("Offline"), "written-offline", "written offline on A, it reaches B once the host is back")
        b.quit()

    def revoke():
        a = App(a_env)
        a.unlock(PW2)
        a.p.type("d")
        a.p.expect(r"add a host")
        a.p.type("1")
        a.p.expect(r"1\s+a-laptop.*\n\s*2\s+b-desk")  # by name
        a.p.expect(r"revoke")
        a.p.type("r 2")
        a.p.expect(r"Type yes to revoke: ")
        a.p.type("yes")
        state["host"].expect(r"Revoke 'b-desk' \(asked by a-laptop\)\?")
        state["host"].type("y")
        a.p.expect(r"Revoked b-desk")
        a.p.type("")
        a.p.type("")
        a.home()
        a.quit()
        b = App(b_env)
        c.check(b.p.saw(r"refuses this computer", 20) is not None,
                "a revoked device: its connector says the host refuses it")
        b.p.type("")  # continue without it
        b.unlock(PW2)
        c.check("Sync error" in b.p.log and "revoked" in b.p.log, "...it can't sync, and says why")
        c.equal(b.password_of("GitHub"), "gh-s3cret-2", "...but keeps its local copy")
        b.quit()

    def pin():
        a = App(a_env)
        a.unlock(PW2)
        a.p.type("")
        legend = a.home().group(2)
        c.check("k PIN" not in legend, "no PIN offered with only a server host (§11)", legend)
        a.quit()

        fake = state["fake"] = fake_host(tmp, "board", FAKE_PORT, FAKE_CODE)
        d_env = sandbox(tmp, "d")
        d = App(d_env)
        d.create(PW)
        d.pair_from_hosts(None, f"127.0.0.1:{FAKE_PORT}", "d-phone", lambda: FAKE_CODE)
        d.p.type("")
        c.check("k PIN" in d.home().group(2), "PIN offered once there's a dedicated host")
        d.p.type("k")
        for prompt, text in ((r"Master password: ", PW), (r"New PIN .*: ", "2468"), (r"Repeat the PIN: ", "2468")):
            d.p.expect(prompt)
            d.p.type(text)
        d.p.expect(r"PIN set")
        pin_file = json.load(open(f"{tmp}/d/cfg/pwvault/pin.json"))
        c.check(len(pin_file.get("host", "")) == 64 and "2468" not in json.dumps(pin_file),
                "pin.json names its host, and doesn't hold the PIN", pin_file)
        d.p.type("l")
        d.p.expect(r"PIN .*: ")
        d.p.type("1111")
        c.check(d.p.saw(r"Wrong PIN\. 4 tries left", 20) is not None, "a wrong PIN: the host counts it (4 left)")
        d.p.expect(r"PIN .*: ")
        d.p.type("2468")
        c.equal(d.home().group(1), "0 entries", "the right PIN unlocks")
        d.quit()
        fake.stop()

    def migration_and_files():
        fake = fake_host(tmp, "old-board", FAKE_PORT + 10, FAKE_CODE)
        e_env = sandbox(tmp, "e", espHost="127.0.0.1", espPort=str(FAKE_PORT + 10))
        r = subprocess.run([f"{ROOT}/esp32/pki.sh", "pair", "e-old"], capture_output=True, text=True,
                           env=dict(e_env, PWVAULT_PAIR_PORT=str(FAKE_PORT + 11), PWVAULT_CODE=FAKE_CODE))
        c.check(r.returncode == 0, "an old-style pairing (esp32/pki.sh pair) into the config", r.stderr)
        e = App(e_env)
        e.create(PW)
        e.quit()
        cfg = f"{tmp}/e/cfg/pwvault"
        config = open(f"{cfg}/config").read()
        moved = glob.glob(f"{cfg}/hosts/*/host")
        c.check("espHost=\n" in config and not os.path.exists(f"{cfg}/device.key") and len(moved) == 1,
                "it moved into hosts/ on the next start (espHost cleared, old files gone)", config)
        c.check(moved and f"address=127.0.0.1:{FAKE_PORT + 10}" in open(moved[0]).read(),
                "...with its address and port")
        fake.stop()

        secrets = glob.glob(f"{tmp}/*/cfg/pwvault/hosts/*/*") + glob.glob(f"{tmp}/host/cfg/pwvault/serve/*") + \
            glob.glob(f"{tmp}/*/cfg/pwvault/pin.json") + glob.glob(f"{tmp}/*/cfg/pwvault/config")
        loose = [p for p in secrets if stat.S_IMODE(os.stat(p).st_mode) != 0o600]
        c.check(len(secrets) > 8 and not loose,
                f"keys, certs, host files, pin.json, configs: all mode 600 ({len(secrets)})", loose)
        dirs = glob.glob(f"{tmp}/*/cfg/pwvault")
        open_dirs = [d for d in dirs if stat.S_IMODE(os.stat(d).st_mode) != 0o700]
        c.check(not open_dirs, "config folders: mode 700", open_dirs)

    def hosts_away():
        # Three paired hosts, all on other networks: the startup check asks them at once, and unlocking right after
        # doesn't wait on them again. 192.0.2.x (TEST-NET-1) never answers, so each attempt is a 1.5 s timeout.
        g_env = sandbox(tmp, "g")
        ports = [FAKE_PORT + 20 + 2 * i for i in range(3)]
        fakes = [fake_host(tmp, f"away{i}", port, FAKE_CODE) for i, port in enumerate(ports)]
        g = App(g_env)
        g.create(PW)
        for i, port in enumerate(ports):
            g.pair_from_hosts(None, f"127.0.0.1:{port}", f"g-{i}", lambda: FAKE_CODE)
        g.quit()
        for f in fakes:
            f.stop()
        for i, path in enumerate(sorted(glob.glob(f"{tmp}/g/cfg/pwvault/hosts/*/host"))):
            text = open(path).read()
            open(path, "w").write(text.replace("address=127.0.0.1:", f"address=192.0.2.{i + 1}:"))
        start = time.time()
        g = App(g_env)
        g.p.expect(r"Master password: ", 30)
        waited = time.time() - start
        c.check(waited < 3.2, f"three hosts away: startup asks them together ({waited:.1f} s; one by one is 4.5+)")
        start = time.time()
        g.p.type(PW)
        g.home()
        unlocking = time.time() - start
        c.check(unlocking < 2.5, f"...and unlocking doesn't wait on them again ({unlocking:.1f} s)")
        c.check("Hosts offline, working on this computer's copy" in g.p.log, "...and says they're offline")
        g.quit()

    for title, fn in (("onboarding: create, pair, join", onboarding), ("edits and deletes", edits),
                      ("wrong master password", wrong_password), ("master password change", master_password),
                      ("offline, then back", offline), ("revoking a device", revoke), ("PIN unlock (§11)", pin),
                      ("an old pairing moves; files on disk", migration_and_files),
                      ("hosts away: no waiting on each in turn", hosts_away)):
        c.run(title, fn)
    state["host"].stop()
    c.done()


if __name__ == "__main__":
    main()
