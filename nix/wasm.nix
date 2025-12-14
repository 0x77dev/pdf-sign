{
  pkgs,
  craneLib,
  lib,
}:
let
  wasmTarget = "wasm32-unknown-unknown";

  src = lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter =
      path: type:
      (lib.hasSuffix "\.rs" path)
      || (lib.hasSuffix "Cargo.toml" path)
      || (lib.hasSuffix "Cargo.lock" path)
      || (lib.hasInfix "/crates/" path)
      || (craneLib.filterCargoSources path type);
  };
in
{
  pdf-sign-wasm = pkgs.stdenv.mkDerivation {
    pname = "pdf-sign-wasm";
    version = "0.1.0";
    inherit src;

    nativeBuildInputs = with pkgs; [
      wasm-pack
      rustc
      cargo
      lld
    ];

    buildPhase = ''
      cd crates/wasm
      wasm-pack build --target web --scope pdf-sign
    '';

    installPhase = ''
      mkdir -p $out
      cp -r pkg/* $out/
    '';

    meta = with lib; {
      description = "pdf-sign WebAssembly bindings";
      platforms = platforms.all;
    };
  };
}
