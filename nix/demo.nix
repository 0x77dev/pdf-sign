{
  pkgs,
  craneLib,
  lib,
}:
let
  autocastSrc = pkgs.fetchFromGitHub {
    owner = "k9withabone";
    repo = "autocast";
    rev = "v0.1.0";
    hash = "sha256-F8RTXcBe3eqzwR48CcU1DpqRzhMBztGIXJrJsQdjgks=";
  };
in
craneLib.buildPackage {
  pname = "autocast";
  src = autocastSrc;
  strictDeps = true;

  meta = with lib; {
    description = "Automate terminal demos";
    homepage = "https://github.com/k9withabone/autocast";
    mainProgram = "autocast";
  };
}
