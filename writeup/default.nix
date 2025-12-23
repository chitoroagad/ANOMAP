{
  nixpkgs,
  typix,
  flake-utils,
  system,
  ...
}: let
  pkgs = nixpkgs.legacyPackages.${system};

  typixLib = typix.lib.${system};

  src = typixLib.cleanTypstSource ./.;

  commonArgs = {
    typstSource = "main.typ";

    fontPaths = [
      # Add paths to fonts here
      # "${pkgs.roboto}/share/fonts/truetype"
      "${pkgs.libertine}/share/fonts/public/truetype"
      "${pkgs.texlivePackages.libertine}/share/fonts/truetype/public"
    ];

    virtualPaths = [
      # Add paths that must be locally accessible to typst here
      # {
      #   dest = "icons";
      #   src = "${inputs.font-awesome}/svgs/regular";
      # }
    ];
  };

  unstable_typstPackages = [
    {
      name = "clean-acmart";
      version = "0.0.1";
      hash = "sha256-47fCSfp+0a052skuRhs7fO1YbnCIcu1jFAY/FpnIi64=";
    }
  ];

  # Compile a Typst project, *without* copying the result
  # to the current directory
  build-drv = typixLib.buildTypstProject (commonArgs
    // {
      inherit src unstable_typstPackages;
    });

  # Compile a Typst project, and then copy the result
  # to the current directory
  build-script = typixLib.buildTypstProjectLocal (commonArgs
    // {
      inherit src unstable_typstPackages;
    });

  build-png-script = typixLib.buildTypstProjectLocal (commonArgs
    // {
      inherit src unstable_typstPackages;
      typstOpts = {
        format = "png";
      };
    });

  # Watch a project and recompile on changes
  watch-script = typixLib.watchTypstProject (commonArgs // {typstWatchCommand = "typst watch --open";});
in {
  checks = {
    inherit build-drv build-script watch-script;
  };

  packages.default = build-drv;

  apps = {
    typst-build = flake-utils.lib.mkApp {
      drv = build-script;
    };
    typst-build-png = flake-utils.lib.mkApp {
      drv = build-png-script;
    };
    typst-build-all = flake-utils.lib.mkApp {
      drv = pkgs.writeShellScriptBin "build-all" ''
        set -e
        ${build-script}/bin/${build-script.pname or "typst-build"}
        ${build-png-script}/bin/${build-png-script.pname or "typst-build"}
      '';
    };
    typst-watch = flake-utils.lib.mkApp {
      drv = watch-script;
    };
  };

  devShells.typst = typixLib.devShell {
    inherit (commonArgs) fontPaths virtualPaths;
    packages = [
      # WARNING: Don't run `typst-build` directly, instead use `nix run .#build`
      # See https://github.com/loqusion/typix/issues/2
      # build-script
      watch-script
      # More packages can be added here, like typstfmt
    ];
  };
}
