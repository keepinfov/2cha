{
  description = "2cha - High-performance VPN utility with IPv4/IPv6 support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ 
            "x86_64-unknown-linux-musl" 
            "aarch64-unknown-linux-musl"
          ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            rust-analyzer
            gcc
            pkg-config
            musl
          ];
          
          RUST_BACKTRACE = 1;
          
          shellHook = ''
            echo "🔐 2cha development environment"
            echo "Rust: $(rustc --version)"
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "2cha";
          version = "0.3.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          
          meta = with pkgs.lib; {
            description = "High-performance VPN utility";
            license = licenses.mit;
          };
        };
        
        # Static musl build
        packages.static = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
          pname = "2cha";
          version = "0.3.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
          
          meta = with pkgs.lib; {
            description = "High-performance VPN utility (static)";
            license = licenses.mit;
          };
        };
      }
    );
}
