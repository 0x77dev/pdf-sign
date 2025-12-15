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

  # Read version from Cargo.toml
  cargoToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  version = cargoToml.workspace.package.version;

  commonArgs = {
    inherit src;
    strictDeps = true;

    # Explicitly set for workspace builds
    pname = "pdf-sign";
    inherit version;

    nativeBuildInputs = with pkgs; [
      pkg-config
      capnproto
    ];
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

      passthru.image = image;
    }
  );

  image = pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/0x77dev/pdf-sign";
    tag = "latest";

    contents = [ pdfSign ];

    config = {
      Cmd = [ "${lib.getExe pdfSign}" ];
      WorkingDir = "/data";
      Env = [
        "GNUPGHOME=/gnupg"
      ];
      Volumes = {
        "/gnupg" = { };
        "/data" = { };
      };
    };
  };
}
