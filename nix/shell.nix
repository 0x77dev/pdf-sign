{
  pkgs,
  pdfSign,
  pre-commit-check,
}:
pkgs.mkShell {
  inputsFrom = [ pdfSign ];

  shellHook = pre-commit-check.shellHook;

  packages =
    with pkgs;
    [
      rustc
      cargo
      rustfmt
      clippy
      pkg-config
      capnproto

      # WASM tooling
      wasm-pack
      wasm-bindgen-cli
      binaryen
      lld

      # Web development
      bun
      nodejs_24
    ]
    ++ pre-commit-check.enabledPackages;
}
