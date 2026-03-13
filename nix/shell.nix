{
  pkgs,
  pdfSign,
  autocast,
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
      cargo-audit
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

      # OCI tooling
      skopeo

      # Demo tools
      asciinema
      autocast
    ]
    ++ pre-commit-check.enabledPackages;
}
