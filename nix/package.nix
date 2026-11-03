{
  rustPlatform,
  src,
}:
rustPlatform.buildRustPackage {
  pname = "cwrunix-sandbox";
  version = "0.1.0";
  inherit src;
  cargoLock.lockFile = "${src}/Cargo.lock";

  # The default installPhase (cargo install) targets one package; install
  # both workspace binaries directly instead.
  installPhase = ''
    runHook preInstall
    install -Dm755 target/*/release/cwrunix-sandbox $out/bin/cwrunix-sandbox
    install -Dm755 target/*/release/cwrunix-subid-map $out/bin/cwrunix-subid-map
    runHook postInstall
  '';
}
