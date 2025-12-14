{
  pkgs,
  craneLib,
  package,
  git-hooks,
  system,
}:
let
  # Our repo's `.cargo/config.toml` sets `[build] target = [...]` for IDE analysis.
  # In Nix builds we typically only have std installed for the host target, so
  # force Cargo to build for the host here to keep `flake check` reproducible.
  cargoTarget =
    if pkgs.stdenv.hostPlatform.isDarwin then "aarch64-apple-darwin" else "x86_64-unknown-linux-gnu";
in
{
  pre-commit-check = import ./git-hooks.nix {
    inherit git-hooks system pkgs;
    src = ../.;
  };

  cargo-test = craneLib.cargoTest (
    package.commonArgs
    // {
      cargoArtifacts = package.cargoArtifacts;
      CARGO_BUILD_TARGET = cargoTarget;
      # Test all workspace members
      cargoTestArgs = "--workspace --all-features";
    }
  );

  pdf-sign-e2e =
    pkgs.runCommand "pdf-sign-e2e"
      {
        nativeBuildInputs = with pkgs; [ gnupg ];
      }
      ''
        export PDF_SIGN="${package.pdfSign}/bin/pdf-sign"
        ${builtins.readFile ../scripts/e2e.sh}
      '';
}
