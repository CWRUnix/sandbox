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
  # the workspace binaries directly instead. cwrunix-jobs dispatches on
  # argv[0]: cwrunix-job = in-sandbox client, cwrunix-jobsd = broker.
  installPhase = ''
    runHook preInstall
    install -Dm755 target/*/release/cwrunix-sandbox $out/bin/cwrunix-sandbox
    install -Dm755 target/*/release/cwrunix-subid-map $out/bin/cwrunix-subid-map
    install -Dm755 target/*/release/cwrunix-jobs $out/bin/cwrunix-job
    ln -s cwrunix-job $out/bin/cwrunix-jobsd
    runHook postInstall
  '';
}
