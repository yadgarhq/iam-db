// Types are GENERATED from the vendored contract, never hand-written (D16). The
// protos come from proto/, vendored at the tag in PROTO_VERSION (D70), so this
// build reaches no network and needs no credentials.
use std::path::Path;

/// Where `google/protobuf/*.proto` lives.
///
/// `buf export` deliberately does not emit the well-known types — protoc is
/// expected to supply them — but a SYSTEM protoc only finds them if its include
/// directory is on the path, and where that is depends on how protoc was
/// installed. Debian's `protobuf-compiler` puts them under `/usr/include`; a nix
/// or Homebrew protoc carries its own and needs nothing added.
///
/// So: honour `PROTOC_INCLUDE` when set, otherwise add `/usr/include` if it
/// actually contains them, otherwise add nothing and let protoc use its own.
/// Adding a directory that does not exist makes protoc fail with a worse message
/// than the one this avoids.
fn well_known_include() -> Option<String> {
    if let Ok(dir) = std::env::var("PROTOC_INCLUDE") {
        return Some(dir);
    }
    Path::new("/usr/include/google/protobuf/timestamp.proto")
        .exists()
        .then(|| "/usr/include".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");

    let mut includes = vec!["proto".to_string()];
    includes.extend(well_known_include());
    let includes: Vec<&str> = includes.iter().map(String::as_str).collect();

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        // Both files: prost generates only for the files it is given, and
        // iamdb.proto merely IMPORTING common.proto does not produce a module
        // for it.
        .compile_protos(
            &[
                "proto/yadgar/common/v1/common.proto",
                "proto/yadgar/iamdb/v1/iamdb.proto",
            ],
            &includes[..],
        )?;
    Ok(())
}
