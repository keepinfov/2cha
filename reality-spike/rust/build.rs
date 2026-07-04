fn main() {
    // The CI step builds libgoreality.a into this crate's directory.
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=goreality");
    // Go's c-archive runtime needs these on Linux.
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rerun-if-changed={dir}/libgoreality.a");
}
