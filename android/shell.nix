# Android build environment: nix-shell android/shell.nix --run 'cd android && gradle assembleDebug'
# Accepting the Android SDK license is required to fetch the SDK.
# --arg withEmulator true adds the emulator and an API 35 x86_64 image (a few GB, once), for the instrumented
# tests: python3 tests/android_test.py (it enters this shell itself).
{ pkgs ? import <nixpkgs> { config = { allowUnfree = true; android_sdk.accept_license = true; }; }, withEmulator ? false }:

let
  android = pkgs.androidenv.composeAndroidPackages ({
    platformVersions = [ "35" ];
    buildToolsVersions = [ "35.0.0" ];
    includeEmulator = withEmulator;
  } // pkgs.lib.optionalAttrs withEmulator {
    includeSystemImages = true;
    systemImageTypes = [ "google_apis" ];
    abiVersions = [ "x86_64" ];
  });
  sdk = "${android.androidsdk}/libexec/android-sdk";
in
pkgs.mkShell {
  buildInputs = [ pkgs.jdk17 pkgs.gradle android.androidsdk pkgs.python3 pkgs.openssl ];
  ANDROID_HOME = sdk;
  # Gradle's own aapt2 download is a generic Linux binary that doesn't run on NixOS; use the SDK's
  GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdk}/build-tools/35.0.0/aapt2";
}
