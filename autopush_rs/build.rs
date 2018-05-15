//! Generate autopush.h via cbindgen
extern crate cbindgen;

use std::{env, fs, path::PathBuf};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR undefined");
    let pkg_name = env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME undefined");
    let target = PathBuf::from(format!("{}/target/{}.h", crate_dir, pkg_name));

    let result = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .generate();
    match result {
        Ok(bindings) => {
            bindings.write_to_file(target);
        }
        Err(e) => {
            eprintln!("cbindgen unable to generate bindings: {}", e);
            if target.exists() {
                fs::remove_file(target).unwrap();
            }
        }
    }
}
