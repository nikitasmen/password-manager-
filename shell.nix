{ pkgs ? import <nixpkgs> {} }:

let
  # Pinned ESP32 core + libraries for esp32/vault; arduino-cli fetches them into ~/.arduino15
  esp32Core = "esp32:esp32@3.3.12";
  esp32Libs = [ "Adafruit SSD1306@2.5.17" "Adafruit GFX Library@1.12.6" "Adafruit BusIO@1.17.4" "ArduinoJson@7.4.3" ];
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build tools
    cmake
    gnumake
    gcc
    pkg-config

    # GUI libraries
    fltk
    libx11
    libxext
    libxft
    libxinerama

    # OpenGL
    mesa
    mesa_glu

    # Fontconfig and XML parser
    fontconfig
    expat

    # System libraries
    openssl
    curl

    # Development tools
    gdb
    valgrind

    # Clipboard
    xclip
    wl-clipboard

    # Json Manipulator
    nlohmann_json

    # ESP32 vault firmware (esp32/vault) and the Python client (clients/python)
    arduino-cli
    (python3.withPackages (ps: [ ps.cryptography ]))
  ];

  ARDUINO_BOARD_MANAGER_ADDITIONAL_URLS = "https://espressif.github.io/arduino-esp32/package_esp32_index.json";

  shellHook = ''
    echo "Password Manager development environment loaded!"

    export CMAKE_PREFIX_PATH="${pkgs.fltk}/lib/cmake:$CMAKE_PREFIX_PATH"
    export PKG_CONFIG_PATH="${pkgs.fltk}/lib/pkgconfig:${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.fontconfig}/lib/pkgconfig:${pkgs.expat}/lib/pkgconfig:$PKG_CONFIG_PATH"
    export CMAKE_PREFIX_PATH="${pkgs.nlohmann_json}/share/cmake:$CMAKE_PREFIX_PATH"

    echo "Ensuring ESP32 toolchain (${esp32Core})"
    [ -f ~/.arduino15/package_esp32_index.json ] || arduino-cli core update-index
    arduino-cli core install ${esp32Core} > /dev/null \
      && arduino-cli lib install ${pkgs.lib.escapeShellArgs esp32Libs} > /dev/null \
      || echo "warning: ESP32 toolchain install failed (offline?); firmware builds may not work"

    echo "Runnig './build.sh' to build the project"
    ./build.sh
'';
}


