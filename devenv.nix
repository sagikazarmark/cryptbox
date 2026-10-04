{ pkgs, ... }:

{
  dagger = {
    enable = true;
    version = "v1.0.0-beta.15";

    dang.enable = true;
  };

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
