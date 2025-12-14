{
  pkgs,
  craneLib,
  lib,
}:
rec {
  # Filter source to include workspace crates
  src = lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter =
      path: type:
      # Keep all Rust source, Cargo files, and the crates directory
      (lib.hasSuffix "\.rs" path)
      || (lib.hasSuffix "Cargo.toml" path)
      || (lib.hasSuffix "Cargo.lock" path)
      || (lib.hasInfix "/crates/" path)
      || (craneLib.filterCargoSources path type);
  };

  commonArgs = {
    inherit src;
    strictDeps = true;

    # Explicitly set for workspace builds
    pname = "pdf-sign";
    version = "0.1.0";

    nativeBuildInputs = with pkgs; [
      pkg-config
      capnproto
    ];

    # Our repo's `.cargo/config.toml` sets `[build] target = [...]` for IDE analysis.
    # In Nix builds we typically only have std installed for the host target, so
    # force Cargo to build for the host here.
    CARGO_BUILD_TARGET =
      if pkgs.stdenv.hostPlatform.isDarwin then "aarch64-apple-darwin" else "x86_64-unknown-linux-gnu";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  pdfSign = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;

      # Build only the CLI binary from the workspace
      cargoExtraArgs = "--bin pdf-sign";

      meta = with lib; {
        description = "Lightweight PDF signing tool with OpenPGP (GPG) and Sigstore (keyless OIDC) backends";
        homepage = "https://github.com/0x77dev/pdf-sign";
        license = licenses.gpl3Only;
        mainProgram = "pdf-sign";
        platforms = platforms.unix;
      };
    }
  );
}
