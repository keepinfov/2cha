// Builds and links the Go REALITY core (native/goreality) as a cgo c-archive when
// the `reality` feature is enabled. A plain `cargo build` (feature off) is a no-op
// and needs no Go toolchain.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("CARGO_FEATURE_REALITY").is_err() {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_dir = manifest.join("../../native/goreality");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let archive = out_dir.join("libgoreality.a");

    let target = env::var("TARGET").unwrap();
    let (goos, goarch) = map_target(&target);

    let mut cmd = Command::new("go");
    cmd.current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-o")
        .arg(&archive)
        .arg(".");
    // cargo-ndk / cross toolchains export a target CC; forward it to cgo.
    if let Ok(cc) = env::var(format!("CC_{}", target.replace('-', "_"))) {
        cmd.env("CC", cc);
    }

    let status = cmd
        .status()
        .expect("failed to run `go build` (is Go 1.24+ installed?)");
    assert!(status.success(), "go build of native/goreality failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=goreality");
    // Go runtime link needs (Linux; on Android these live in Bionic libc).
    if goos == "linux" {
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=resolv");
    }
    println!("cargo:rerun-if-changed={}/goreality.go", go_dir.display());
    println!("cargo:rerun-if-changed={}/go.mod", go_dir.display());
}

fn map_target(target: &str) -> (&'static str, &'static str) {
    let arch = if target.contains("aarch64") {
        "arm64"
    } else if target.contains("x86_64") {
        "amd64"
    } else if target.contains("armv7") || target.contains("arm-") {
        "arm"
    } else if target.contains("i686") {
        "386"
    } else {
        panic!("goreality: unsupported target arch: {target}");
    };
    let os = if target.contains("android") {
        "android"
    } else if target.contains("linux") {
        "linux"
    } else if target.contains("darwin") || target.contains("apple") {
        "darwin"
    } else {
        panic!("goreality: unsupported target OS: {target}");
    };
    (os, arch)
}
