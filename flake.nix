

{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = { self, nixpkgs, utils, naersk, flake-compat }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in
      {
        defaultPackage = with pkgs; naersk-lib.buildPackage {
          nativeBuildInputs = [ cargo rustc rustPlatform.bindgenHook pkg-config cmake ];
          buildInputs = [ sqlite openssl ];
          src = ./.; 
          cargoOptions = (opts: opts ++ [ "--locked" ]);
        };

        devShell = with pkgs; mkShell {
          strictDeps = true;
          # Required for build
          nativeBuildInputs = [ cargo rustc rustPlatform.bindgenHook pkg-config cmake ];
          # System dependencies
          buildInputs = [ sqlite openssl ];
          # Env dependencies
          packages = [ rustPackages.clippy rust-analyzer pre-commit cargo-expand rustfmt ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}

