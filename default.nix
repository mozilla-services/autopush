with import <nixpkgs> {}; {
  pyEnv = stdenv.mkDerivation {
    name = "autopush-env";
    buildInputs = [ stdenv gcc python27Full python27Packages.virtualenv readline libffi openssl openjdk7 gnumake ];
    shellHook = ''
      if [ ! -d pypy ]
      then
        virtualenv -p $(nix-build -A pythonFull '<nixpkgs>')/bin/python pypy
      fi
      source pypy/bin/activate
      if [ ! -e `pwd`/pypy/bin/pypy ]
      then
        ln -s `pwd`/pypy/bin/python `pwd`/pypy/bin/pypy
      fi
      if [ ! -d ddb ]
      then
        make travis
      fi
    '';
  };
}
