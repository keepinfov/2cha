{
  description = "2cha - High-performance VPN utility with IPv4/IPv6 support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } ({ self, ... }: {
      systems = [ "x86_64-linux" "aarch64-linux" ];

      # Per-system packages / apps / devShells (see nix/package.nix).
      imports = [ ./nix/package.nix ];

      # System-independent outputs.
      flake = {
        # Overlay for use in other flakes.
        overlays.default = final: prev: {
          twocha = self.packages.${prev.system}.default;
        };

        # Declarative NixOS module (see nix/nixos-module.nix).
        nixosModules.default = import ./nix/nixos-module.nix { inherit self; };
        nixosModules.twocha = self.nixosModules.default;
      };
    });
}
