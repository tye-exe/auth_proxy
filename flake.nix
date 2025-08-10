{
  description = "Environment a standalone authentication proxy.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rust-build = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" ];
        };
      in
      {
        devShells.default =
          with pkgs;
          mkShell {

            nativeBuildInputs = [
              pkg-config
              openssl
            ];

            buildInputs = [
              rust-build
              sqlx-cli
              bacon
            ];

            DATABASE_URL = "sqlite:database.sqlite3";
          };
      }
    );
}
