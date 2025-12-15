{
  description = "2cha - High-performance VPN utility with IPv4/IPv6 support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, flake-compat, ... }:
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

        # Common package attributes
        commonAttrs = {
          pname = "2cha";
          version = "0.7.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "High-performance VPN utility with IPv4/IPv6 support";
            homepage = "https://github.com/keepinfov/2cha";
            license = licenses.mit;
            maintainers = [];
            mainProgram = "2cha";
            platforms = platforms.linux;
          };
        };

        # Default package (dynamic linking)
        twocha = pkgs.rustPlatform.buildRustPackage (commonAttrs // {
          nativeBuildInputs = with pkgs; [ pkg-config ];
        });

        # Static musl build
        muslTarget = {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
        }.${system} or (throw "Unsupported system for static build: ${system}");

        twochaStatic = pkgs.pkgsStatic.rustPlatform.buildRustPackage (commonAttrs // {
          pname = "2cha-static";
          nativeBuildInputs = with pkgs.pkgsStatic; [ pkg-config ];

          CARGO_BUILD_TARGET = muslTarget;
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

          meta = commonAttrs.meta // {
            description = "High-performance VPN utility (statically linked)";
          };
        });

      in
      {
        # Packages
        packages = {
          default = twocha;
          "2cha" = twocha;
          static = twochaStatic;
        };

        # Apps for `nix run`
        apps = {
          default = {
            type = "app";
            program = "${twocha}/bin/2cha";
          };
          "2cha" = {
            type = "app";
            program = "${twocha}/bin/2cha";
          };
          static = {
            type = "app";
            program = "${twochaStatic}/bin/2cha";
          };
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            rust-analyzer
            cargo-watch
            gcc
            pkg-config
            musl
          ];

          RUST_BACKTRACE = 1;
          RUST_LOG = "debug";

          shellHook = ''
            echo "2cha development environment"
            echo "Rust: $(rustc --version)"
            echo ""
            echo "Commands:"
            echo "  cargo build --release              # Build release"
            echo "  cargo run -- --help                # Run with args"
            echo "  nix build                          # Build with Nix"
            echo "  nix build .#static                 # Build static binary"
          '';
        };
      }
    ) // {
      # Overlay for use in other flakes
      overlays.default = final: prev: {
        twocha = self.packages.${prev.system}.default;
      };
    };
}
