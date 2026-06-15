{ inputs, ... }:
{
  perSystem = { system, ... }:
    let
      overlays = [ (import inputs.rust-overlay) ];
      pkgs = import inputs.nixpkgs { inherit system overlays; };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [
          "x86_64-unknown-linux-musl"
          "aarch64-unknown-linux-musl"
        ];
      };

      # Common package attributes
      commonAttrs = {
        pname = "2cha";
        version = "1.3.0";
        src = ../.;
        cargoLock.lockFile = ../Cargo.lock;

        meta = with pkgs.lib; {
          description = "High-performance VPN utility with IPv4/IPv6 support";
          homepage = "https://github.com/keepinfov/2cha";
          license = licenses.mit;
          maintainers = [ ];
          mainProgram = "2cha";
          platforms = platforms.linux;
        };
      };

      # Default package (dynamic linking)
      twocha = pkgs.rustPlatform.buildRustPackage (commonAttrs // {
        nativeBuildInputs = with pkgs; [ pkg-config ];

        # The transport roundtrip tests open real loopback sockets and drive a
        # full TLS 1.3 handshake across threads. Inside the Nix build sandbox
        # they are timing-fragile and have no internal timeout, so they can
        # wedge the build indefinitely. They are exercised by regular CI /
        # `cargo test`; skip them here so the sandboxed build stays hermetic.
        checkFlags = [
          "--skip=tls_loopback_roundtrip"
          "--skip=udp_carrier_roundtrip_preserves_datagrams"
          "--skip=run_mobile_loopback_roundtrip"
        ];
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

        # Don't re-run the full (LTO) test suite for the static target: it is
        # already covered by the dynamic build, and running the musl test
        # binaries here roughly doubles build time for no extra signal.
        doCheck = false;

        meta = commonAttrs.meta // {
          description = "High-performance VPN utility (statically linked)";
        };
      });
    in
    {
      packages = {
        default = twocha;
        "2cha" = twocha;
        static = twochaStatic;
      };

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
    };
}
