{
  description = "pdf-sign: lightweight PDF signing with OpenPGP (GPG) and Sigstore (keyless OIDC)";

  nixConfig = {
    extra-substituters = [
      "https://pdf-sign.cachix.org"
    ];
    extra-trusted-public-keys = [
      "pdf-sign.cachix.org-1:RjOq/uF6ksxVZsLfI9+SW4Nkhcc63+klWAoAtkZRF2U="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    git-hooks.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      git-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
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

        packages = {
          default = package.pdfSign;
          pdf-sign = package.pdfSign;
          pdf-sign-wasm =
            (import ./nix/wasm.nix {
              inherit pkgs craneLib;
              lib = pkgs.lib;
            }).pdf-sign-wasm;
        };

        devShells.default = import ./nix/shell.nix {
          inherit pkgs;
          pdfSign = package.pdfSign;
          pre-commit-check = import ./nix/git-hooks.nix {
            inherit git-hooks system pkgs;
            src = ./.;
          };
        };
      }
    );
}
