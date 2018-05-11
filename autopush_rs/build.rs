//! Generate autopush.h via cbindgen
extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR undefined");
    let pkg_name = env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME undefined");
    let target = format!("{}/target/{}.h", crate_dir, pkg_name);
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("cbindgen unable to generate bindings")
        .write_to_file(target.as_str());
}
