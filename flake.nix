{
  description = "CWRUnix login sandbox: namespace launcher + subid map helper";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        cwrunix-sandbox = pkgs.callPackage ./nix/package.nix { src = self; };
        treefmtconfig = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            nixfmt.enable = true;
            rustfmt = {
              enable = true;
              edition = "2021";
            };
          };
        };
      in
      {
        packages = {
          default = cwrunix-sandbox;
          inherit cwrunix-sandbox;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            nil
            nixd
          ];
        };

        formatter = treefmtconfig.config.build.wrapper;
        checks.formatting = treefmtconfig.config.build.check self;
      }
    );
}
