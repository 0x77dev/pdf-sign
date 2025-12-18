{
  git-hooks,
  system,
  pkgs,
  src ? ../.,
}:

git-hooks.lib.${system}.run {
  inherit src;

  hooks = {
    nixfmt.enable = true;
    shellcheck.enable = true;
    rustfmt.enable = true;
  };

  package = pkgs.prek;
}
