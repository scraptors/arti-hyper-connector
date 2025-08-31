

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
        defaultPackage = naersk-lib.buildPackage { 
          src = ./.; 
        };
        devShell = with pkgs; mkShell {
          strictDeps = true;

          nativeBuildInputs = [ cargo rustc rustPlatform.bindgenHook pkg-config cmake ];

          buildInputs = [ sqlite openssl ];

          packages = [ rustPackages.clippy  rust-analyzer ];

          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}

