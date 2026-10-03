"""Shared by the end-to-end suites (serve_test.py, api_test.py, e2e_test.py): processes driven like a person at a
terminal, sandboxed config folders, fake hosts, and strict checks. Nothing here touches the real board or the
user's ~/.config/pwvault: every process gets XDG_CONFIG_HOME/XDG_DATA_HOME in a temp dir.

Run the suites from the repo root after a build, in a shell with openssl, curl and python3:
  nix-shell -p openssl curl python3 --run 'python3 tests/api_test.py'
"""
import atexit
import os
import queue
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = f"{ROOT}/password_manager"
children = []  # killed on any exit: a host left running keeps its port, and the next run meets its cert
atexit.register(lambda: [c.kill() for c in children if c.poll() is None])


class Proc:
    """A process with a pipe for its terminal. Output is read as it comes: prompts end without a newline."""

    def __init__(self, argv, env=None):
        self.p = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        children.append(self.p)
        self.chunks = queue.Queue()
        self.seen = ""  # output not matched yet
        self.log = ""  # everything, for failure messages
        threading.Thread(target=lambda: [self.chunks.put(c) for c in iter(lambda: os.read(self.p.stdout.fileno(),
                         4096), b"")], daemon=True).start()

    def type(self, line):
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()

    def _pull(self, timeout):
        try:
            text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", self.chunks.get(timeout=timeout).decode(errors="replace"))
        except queue.Empty:
            return False
        self.seen += text
        self.log += text
        return True

    def expect(self, pattern, seconds=20):
        """Waits for output matching `pattern` and consumes it up to the match. Fails the run if it never comes."""
        until = time.time() + seconds
        while True:
            if m := re.search(pattern, self.seen):
                self.seen = self.seen[m.end():]
                return m
            if time.time() > until:
                raise AssertionError(f"no output matching {pattern!r}; last output: {self.log[-600:]!r}")
            self._pull(0.2)

    def saw(self, pattern, seconds=2):
        """Like expect, but returns None instead of failing."""
        try:
            return self.expect(pattern, seconds)
        except AssertionError:
            return None

    def stop(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait(10)


class Checks:
    """Strict assertions, each reported; the suite's exit code is the number that failed."""

    def __init__(self, suite):
        self.suite, self.failed, self.passed = suite, [], 0

    def check(self, ok, what, detail=""):
        print(("ok    " if ok else "FAIL  ") + what + ("" if ok or not detail else f"\n        {detail}"), flush=True)
        if ok:
            self.passed += 1
        else:
            self.failed.append(what)
        return ok

    def equal(self, got, want, what):
        return self.check(got == want, what, f"got {got!r}, want {want!r}")

    def section(self, title):
        print(f"\n== {title}", flush=True)

    def run(self, title, fn, *args):
        """A block of checks; an exception in it is one more failure, and the next block still runs."""
        self.section(title)
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001 - any error is a failed block, reported with its message
            self.check(False, f"{title}: finished", f"{type(e).__name__}: {e}")

    def done(self):
        print(f"\n{self.suite}: {self.passed} passed, {len(self.failed)} failed")
        for f in self.failed:
            print(f"  FAIL {f}")
        sys.exit(1 if self.failed else 0)


def sandbox(tmp, name, **config):
    """XDG dirs of their own; `config` keys are written to its pwvault config (e.g. espHost=..., localCopy=false)."""
    os.makedirs(f"{tmp}/{name}/cfg/pwvault", exist_ok=True)
    if config:
        with open(f"{tmp}/{name}/cfg/pwvault/config", "w") as f:
            f.write("".join(f"{k}={v}\n" for k, v in config.items()))
    return dict(os.environ, XDG_CONFIG_HOME=f"{tmp}/{name}/cfg", XDG_DATA_HOME=f"{tmp}/{name}/data")


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def new_server_cert(tmp, name):
    """A host's self-signed cert for pwvault.local: a fake needs its own, since the cert's SHA-256 is the host id."""
    cert, key = f"{tmp}/{name}.pem", f"{tmp}/{name}.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
            "-subj", "/CN=pwvault.local", "-addext", "subjectAltName=DNS:pwvault.local", "-keyout", key, "-out", cert)
    return cert, key


def fake_host(tmp, name, port, code, role="dedicated"):
    """tests/fake_esp.py with its own cert and device CA. Pairing is always open with `code`, approval automatic."""
    cert, key = new_server_cert(tmp, f"{name}-server")
    os.makedirs(f"{tmp}/{name}-ca", exist_ok=True)
    p = Proc([sys.executable, f"{ROOT}/tests/fake_esp.py", "--port", str(port), "--cert", cert, "--key", key,
              "--ca-dir", f"{tmp}/{name}-ca", "--code", code, "--role", role])
    p.expect(r"fake ESP32 on")
    return p


def serve_host(env, port, role="server"):
    """`password_manager --serve`, ready to answer."""
    p = Proc([APP, "--serve", "--port", str(port), "--role", role], env)
    p.expect(r"Serving .* as a " + role + " host")
    return p
