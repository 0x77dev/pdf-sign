{
  pkgs,
  craneLib,
  package,
  git-hooks,
  system,
}:
let
  # Ensure we build for the host Rust target triple.
  #
  # This avoids picking an incorrect default target in CI (e.g. forcing x86_64
  # on aarch64) and keeps `flake check` reproducible across platforms.
  cargoTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget or pkgs.stdenv.hostPlatform.config;
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
