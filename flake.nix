{
  description = "pdf-sign: lightweight PDF signing with OpenPGP (GPG) and Sigstore (keyless OIDC)";

  nixConfig = {
    extra-substituters = [
      "https://pdf-sign.cachix.org"
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "pdf-sign.cachix.org-1:RjOq/uF6ksxVZsLfI9+SW4Nkhcc63+klWAoAtkZRF2U="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    git-hooks.url = "github:cachix/git-hooks.nix";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      git-hooks,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        craneLib = crane.mkLib pkgs;

        package = import ./nix/package.nix {
          inherit pkgs craneLib;
          lib = pkgs.lib;
        };
      in
      {
        checks = import ./nix/checks.nix {
          inherit
            pkgs
            craneLib
            package
            git-hooks
            system
            ;
        };

        packages =
          let
            autocast = import ./nix/demo.nix {
              inherit pkgs craneLib;
              lib = pkgs.lib;
            };
          in
          {
            default = package.pdfSign;
            pdf-sign = package.pdfSign;
            inherit autocast;
          };

        devShells.default = import ./nix/shell.nix {
          inherit pkgs;
          pdfSign = package.pdfSign;
          autocast = import ./nix/demo.nix {
            inherit pkgs craneLib;
            lib = pkgs.lib;
          };
          pre-commit-check = import ./nix/git-hooks.nix {
            inherit git-hooks system pkgs;
            src = ./.;
          };
        };
      }
    );
}
