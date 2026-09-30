# Android build environment: nix-shell android/shell.nix --run 'cd android && gradle assembleDebug'
# Accepting the Android SDK license is required to fetch the SDK.
{ pkgs ? import <nixpkgs> { config = { allowUnfree = true; android_sdk.accept_license = true; }; } }:

let
  android = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "35" ];
    buildToolsVersions = [ "35.0.0" ];
    includeEmulator = false;
  };
  sdk = "${android.androidsdk}/libexec/android-sdk";
in
pkgs.mkShell {
  buildInputs = [ pkgs.jdk17 pkgs.gradle android.androidsdk pkgs.python3 pkgs.openssl ];
  ANDROID_HOME = sdk;
  # Gradle's own aapt2 download is a generic Linux binary that doesn't run on NixOS; use the SDK's
  GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdk}/build-tools/35.0.0/aapt2";
}
