extern crate cbindgen;

use std::env;
use std::path::{Path, PathBuf};

#[path = "src/security_inputs.rs"]
#[allow(dead_code)]
mod security_inputs;

// See:
// <https://github.com/eqrion/cbindgen/blob/master/docs.md#buildrs>
// <https://doc.rust-lang.org/cargo/reference/build-scripts.html>
// <https://doc.rust-lang.org/cargo/reference/build-script-examples.html>
fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Each header is generated from a single source file. cbindgen scans
    // exactly that file and emits the `pub extern "C"` items it defines plus
    // the C types they reference. Since each bucket file is self-contained
    // (defines its own types), there is no cross-bucket leak and no need for
    // exclusion lists in the cbindgen configs.
    generate_header(
        &crate_dir,
        "cbindgen_dart.toml",
        "src/c_api/dart.rs",
        "include/updater_dart.h",
    );
    generate_header(
        &crate_dir,
        "cbindgen_engine.toml",
        "src/c_api/engine.rs",
        "include/updater_engine.h",
    );
    generate_compiled_security_policy();
}

/// Validates the SHOREBIRD_SECURITY_* build environment and writes the
/// compiled security floor into OUT_DIR. An invalid or reserved input fails
/// the build: a hardened updater can never be produced without its
/// toolchain identity, and `hardened-diversified` is rejected (contract v1).
fn generate_compiled_security_policy() {
    // Declaring any rerun-if-* disables cargo's default "rerun when any
    // package file changes", so keep the header inputs explicit as well.
    for path in [
        "build.rs",
        "Cargo.toml",
        "cbindgen_dart.toml",
        "cbindgen_engine.toml",
        "src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    let mut values = Vec::new();
    for name in security_inputs::ALL_ENV {
        println!("cargo:rerun-if-env-changed={name}");
        values.push(match env::var(name) {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => panic!("{name} is not valid UTF-8"),
        });
    }
    let inputs = security_inputs::parse_compiled_inputs(
        values[0].as_deref(),
        values[1].as_deref(),
        values[2].as_deref(),
        values[3].as_deref(),
        values[4].as_deref(),
    )
    .unwrap_or_else(|error| panic!("Invalid compiled security policy: {error}"));
    if inputs.development_exceptions {
        println!(
            "cargo:warning=Building a DEVELOPMENT-ONLY hardened updater \
             (loopback HTTP allowed); production packaging rejects it"
        );
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(
        out.join("compiled_security_policy.rs"),
        security_inputs::render_compiled_policy(&inputs),
    )
    .expect("write compiled_security_policy.rs");
}

fn generate_header(crate_dir: &Path, config_name: &str, src_relative: &str, output_path: &str) {
    let config_path = crate_dir.join(config_name);
    let config = match cbindgen::Config::from_file(&config_path) {
        Ok(config) => config,
        Err(e) => {
            println!("cargo:warning=Error loading {}: {e}", config_path.display());
            return;
        }
    };

    let src_path = crate_dir.join(src_relative);
    let result = cbindgen::Builder::new()
        .with_src(&src_path)
        .with_config(config)
        .generate();
    match result {
        Ok(contents) => {
            contents.write_to_file(output_path);
        }
        Err(e) => {
            println!("cargo:warning=Error generating {output_path}: {e}");
            // We don't exit non-zero here so local rust-analyzer keeps
            // working when cbindgen has an issue.
        }
    }
}
