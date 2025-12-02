{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "2cha-dev";
  
  buildInputs = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    gcc
    pkg-config
    
    # For static musl builds
    musl
    # musl.dev  # Uncomment if needed
  ];

  # For cross-compilation
  nativeBuildInputs = with pkgs; [
    # pkgsCross.aarch64-multiplatform.stdenv.cc  # ARM64 cross-compiler
  ];

  RUST_BACKTRACE = 1;

  shellHook = ''
    echo "🔐 2cha development environment"
    echo ""
    echo "Commands:"
    echo "  cargo build --release              # Build release"
    echo "  cargo build --release --target x86_64-unknown-linux-musl  # Static build"
    echo ""
    echo "Targets available:"
    rustup target list --installed 2>/dev/null || echo "  (run 'rustup target list')"
  '';
}
