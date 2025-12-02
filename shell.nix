{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "2cha-dev";
  
  buildInputs = with pkgs; [
    rustc
    cargo
    gcc
    pkg-config
  ];

  shellHook = ''
    echo "🔐 2cha development environment"
    echo "   Build: cargo build --release"
  '';
}
