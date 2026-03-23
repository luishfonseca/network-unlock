{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = {...} @ inputs: let
    eachSystem = inputs.nixpkgs.lib.genAttrs (import inputs.systems);
    pkgs = eachSystem (system: import inputs.nixpkgs {inherit system;});
    package = pkgs: pkgs.callPackage ./. {};
  in {
    packages = eachSystem (system: rec {
      networkUnlock = package pkgs.${system};
      default = networkUnlock;
    });

    legacyPackages = eachSystem (system: {
      networkUnlock = package pkgs.${system};
    });

    overlays = rec {
      networkUnlock = final: prev: {
        networkUnlock = package prev;
      };
      default = networkUnlock;
    };

    nixosModules = rec {
      server = import ./modules/server.nix inputs;
      client = import ./modules/client.nix inputs;
      networkUnlock = {imports = [server client];};
      default = networkUnlock;
    };

    formatter = eachSystem (system: pkgs.${system}.alejandra);
  };
}
