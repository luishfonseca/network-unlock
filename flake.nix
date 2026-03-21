{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = {
    self,
    systems,
    nixpkgs,
  }: let
    eachSystem = nixpkgs.lib.genAttrs (import systems);
    pkgs = eachSystem (system: import nixpkgs {inherit system;});
  in {
    packages = eachSystem (system: rec {
      network-unlock = pkgs.${system}.callPackage ./. {};
      default = network-unlock;
    });

    formatter = eachSystem (system: pkgs.${system}.alejandra);
  };
}
