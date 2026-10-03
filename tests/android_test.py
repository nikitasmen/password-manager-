#!/usr/bin/env python3
"""The Android app's instrumented tests (android/src/androidTest): App with Keystore keys, its files, and the real
screens, against two fakes on this computer, on a headless emulator (or a connected phone).

  nix-shell android/shell.nix --run 'python3 tests/android_test.py [--keep]'   # repo root
  (--keep leaves the emulator running for the next run; the shell provides python3 and openssl for the fakes)

It starts tests/fake_esp.py twice (a dedicated board and a server host), boots an API 35 emulator from
android/shell.nix --arg withEmulator true (needs /dev/kvm; the AVD lives in android/build/avd), and runs
`gradle connectedDebugAndroidTest`, telling the tests where the fakes are (10.0.2.2 is this computer, seen from
the emulator). A phone already connected over adb is used instead of an emulator; then the fakes are reached
through `adb reverse`, as 127.0.0.1.
"""
import functools
import os
import subprocess
import sys
import tempfile
import time

from harness import ROOT, Proc, fake_host

print = functools.partial(print, flush=True)  # noqa: A001 - progress shows as it happens, even into a pipe

ANDROID = f"{ROOT}/android"
AVD_HOME = f"{ANDROID}/build/avd"
AVD, IMAGE = "pwvault-test", "system-images;android-35;google_apis;x86_64"
BOARD, SERVER = 19443, 19453
CODE_B, CODE_S = "ABCD0123EFGH4567", "BCDE1234FGHJ5678"
SHELL = ["nix-shell", f"{ANDROID}/shell.nix", "--arg", "withEmulator", "true", "--run"]
ENV = dict(os.environ, ANDROID_AVD_HOME=AVD_HOME, ANDROID_USER_HOME=f"{ANDROID}/build/android-home")


def sh(cmd, check=True, **kw):
    return subprocess.run(SHELL + [cmd], env=ENV, cwd=ANDROID, capture_output=True, text=True, check=check, **kw)


def devices():
    out = sh("adb devices", check=False).stdout.splitlines()[1:]
    return [line.split()[0] for line in out if line.endswith("device")]


def main():
    keep = "--keep" in sys.argv
    tmp = tempfile.mkdtemp(prefix="android_test_")
    fakes = [fake_host(tmp, "board", BOARD, CODE_B), fake_host(tmp, "server", SERVER, CODE_S, role="server")]
    emulator = None
    phone = [d for d in devices() if not d.startswith("emulator-")]
    if phone:
        print(f"using the connected device {phone[0]}; the fakes go through adb reverse")
        for port in (BOARD, BOARD + 1, SERVER, SERVER + 1):
            sh(f"adb reverse tcp:{port} tcp:{port}")
        host = "127.0.0.1"
    else:
        host = "10.0.2.2"
        if not devices():
            os.makedirs(AVD_HOME, exist_ok=True)
            if not os.path.exists(f"{AVD_HOME}/{AVD}.avd"):
                print("creating the emulator (once)")
                sh(f"echo no | avdmanager create avd -n {AVD} -k '{IMAGE}' -d pixel_6 --force")
            print("booting the emulator")
            emulator = Proc(SHELL + [f"emulator -avd {AVD} -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect "
                                     "-no-snapshot-save -memory 2048"], ENV)
            sh("adb wait-for-device", timeout=300)
            until = time.time() + 300
            while sh("adb shell getprop sys.boot_completed", check=False).stdout.strip() != "1":
                if time.time() > until:
                    sys.exit(f"the emulator didn't boot; its output: {emulator.log[-2000:]}")
                time.sleep(3)
            sh("adb shell settings put global window_animation_scale 0 && "
               "adb shell settings put global transition_animation_scale 0 && "
               "adb shell settings put global animator_duration_scale 0", check=False)
    args = (f"-Pandroid.testInstrumentationRunnerArguments.board={host}:{BOARD} "
            f"-Pandroid.testInstrumentationRunnerArguments.boardCode={CODE_B} "
            f"-Pandroid.testInstrumentationRunnerArguments.server={host}:{SERVER} "
            f"-Pandroid.testInstrumentationRunnerArguments.serverCode={CODE_S}")
    print("running the instrumented tests")
    r = subprocess.run(SHELL + [f"gradle connectedDebugAndroidTest {args}"], env=ENV, cwd=ANDROID)
    print(f"report: {ANDROID}/build/reports/androidTests/connected/debug/index.html")
    for f in fakes:
        f.stop()
    if emulator and not keep:
        sh("adb emu kill", check=False)
        emulator.stop()
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
