# NixOS module — declarative `services.twocha.{server,client}`.
#
# The config is rendered from Nix options into the (read-only) Nix store and
# passed to the daemon with `-c`. This is the source of truth: to add a peer,
# add it to `services.twocha.server.settings.peers` and rebuild. A runtime
# `2cha peer add` still live-authorises on the control socket but cannot persist
# into the store config (it replies "not persisted").
#
# On non-NixOS hosts none of this is needed: use the `init` wizard and the
# imperative `2cha config` / `2cha peer` commands against /etc/2cha/*.toml.
{ self }:
{ config, lib, pkgs, ... }:
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
}
