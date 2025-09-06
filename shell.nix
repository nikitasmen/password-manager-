{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build tools
    cmake
    gnumake
    gcc
    pkg-config

    # GUI libraries
    fltk
    xorg.libX11
    xorg.libXext
    xorg.libXft
    xorg.libXinerama

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
  ];

  shellHook = ''
    echo "Password Manager development environment loaded!"
    echo "Run './build.sh' to build the project"

    export CMAKE_PREFIX_PATH="${pkgs.fltk}/lib/cmake:$CMAKE_PREFIX_PATH"
    export PKG_CONFIG_PATH="${pkgs.fltk}/lib/pkgconfig:${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.fontconfig}/lib/pkgconfig:${pkgs.expat}/lib/pkgconfig:$PKG_CONFIG_PATH"
  '';
}


