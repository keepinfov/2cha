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
          version = "1.2.0";
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

          # The transport roundtrip tests open real loopback sockets and drive a
          # full TLS 1.3 handshake across threads. Inside the Nix build sandbox
          # they are timing-fragile and have no internal timeout, so they can
          # wedge the build indefinitely. They are exercised by regular CI /
          # `cargo test`; skip them here so the sandboxed build stays hermetic.
          checkFlags = [
            "--skip=tls_loopback_roundtrip"
            "--skip=udp_carrier_roundtrip_preserves_datagrams"
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

      # ─────────────────────────────────────────────────────────────────────
      # NixOS module — declarative `services.twocha.{server,client}`.
      #
      # The config is rendered from Nix options into the (read-only) Nix store
      # and passed to the daemon with `-c`. This is the source of truth: to add
      # a peer, add it to `services.twocha.server.settings.peers` and rebuild.
      # A runtime `2cha peer add` still live-authorises on the control socket
      # but cannot persist into the store config (it replies "not persisted").
      #
      # On non-NixOS hosts none of this is needed: use the `init` wizard and the
      # imperative `2cha config` / `2cha peer` commands against /etc/2cha/*.toml.
      # ─────────────────────────────────────────────────────────────────────
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          inherit (lib) mkIf mkOption mkEnableOption types mkMerge optionalString recursiveUpdate;
          cfg = config.services.twocha;
          settingsFormat = pkgs.formats.toml { };
          defaultPackage = self.packages.${pkgs.system}.default;

          sideOptions = role: {
            enable = mkEnableOption "the 2cha VPN ${role}";

            package = mkOption {
              type = types.package;
              default = defaultPackage;
              defaultText = lib.literalExpression "twocha.packages.\${system}.default";
              description = "The 2cha package to run.";
            };

            settings = mkOption {
              type = settingsFormat.type;
              default = { };
              description = ''
                Free-form 2cha ${role} configuration, rendered to TOML. Mirrors
                the sections documented in docs/configuration.md. `crypto.private_key_file`
                is set automatically from `privateKeyFile`.
              '';
            };

            privateKeyFile = mkOption {
              type = types.path;
              description = ''
                Path to the raw 32-byte X25519 private key (mode 0600). Keep this
                out of the Nix store — manage it with sops-nix/agenix, or let
                `generateKey` create it on first start.
              '';
            };

            generateKey = mkOption {
              type = types.bool;
              default = false;
              description = "Run `2cha genkey` in a pre-start step to create privateKeyFile if it is missing.";
            };

            openFirewall = mkOption {
              type = types.bool;
              default = false;
              description = "Open the server's listen port in the firewall (UDP for quic, TCP for tls).";
            };
          };

          mkConfigFile = role: side:
            settingsFormat.generate "2cha-${role}.toml"
              (recursiveUpdate side.settings {
                crypto.private_key_file = toString side.privateKeyFile;
              });

          mkService = role: side: subcmd:
            let
              configFile = mkConfigFile role side;
            in
            {
              description = "2cha VPN ${role}";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              preStart = optionalString side.generateKey ''
                if [ ! -e "${toString side.privateKeyFile}" ]; then
                  mkdir -p "$(dirname "${toString side.privateKeyFile}")"
                  ${side.package}/bin/2cha genkey "${toString side.privateKeyFile}"
                fi
              '';
              serviceConfig = {
                ExecStart = "${side.package}/bin/2cha ${subcmd} -c ${configFile}";
                Restart = "on-failure";
                RestartSec = 5;
                # TUN device creation and netlink routing require CAP_NET_ADMIN.
                AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
                CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
                DeviceAllow = [ "/dev/net/tun rw" ];
                RuntimeDirectory = "2cha";
                ProtectHome = true;
                ProtectControlGroups = true;
                ProtectKernelTunables = false; # server toggles ip_forward via /proc when gateway is on
                NoNewPrivileges = true;
              };
            };

          serverPort =
            let parts = lib.splitString ":" (cfg.server.settings.server.listen or "0.0.0.0:51820");
            in lib.toInt (lib.last parts);
          serverIsTls = (cfg.server.settings.server.transport or "quic") == "tls";
        in
        {
          options.services.twocha = {
            server = sideOptions "server";
            client = sideOptions "client";
          };

          config = mkMerge [
            (mkIf cfg.server.enable {
              assertions = [{
                assertion = (cfg.server.settings.server.listen or null) != null;
                message = "services.twocha.server.settings.server.listen must be set (e.g. \"0.0.0.0:51820\").";
              }];
              systemd.services."2cha-server" = mkService "server" cfg.server "server";
              networking.firewall = mkIf cfg.server.openFirewall (
                if serverIsTls
                then { allowedTCPPorts = [ serverPort ]; }
                else { allowedUDPPorts = [ serverPort ]; }
              );
            })
            (mkIf cfg.client.enable {
              assertions = [{
                assertion = (cfg.client.settings.client.server or null) != null;
                message = "services.twocha.client.settings.client.server must be set (e.g. \"vpn.example.com:51820\").";
              }];
              systemd.services."2cha-client" = mkService "client" cfg.client "up";
            })
          ];
        };

      nixosModules.twocha = self.nixosModules.default;
    };
}
