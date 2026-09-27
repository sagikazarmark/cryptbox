{ pkgs, ... }:

{

  dagger.enable = true;
  env.DAGGER_X_RELEASE = "v1.0.0-beta.14";

  packages = with pkgs; [
    lld
    cargo-audit
    cargo-deny
    cargo-dist
    cargo-hack
    cargo-release
    cargo-watch

    lychee
  ];

  languages = {
    rust = {
      enable = true;
    };
  };
}
