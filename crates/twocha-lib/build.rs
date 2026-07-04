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

    let target = env::var("TARGET").unwrap();
    let (goos, goarch) = map_target(&target);

    // Go can't emit a c-archive for android (`-buildmode=c-archive not supported
    // on android/*`), so on Android we build a c-shared `.so` and link it
    // dynamically; everywhere else we keep the self-contained static archive.
    let is_android = goos == "android";
    let (buildmode, lib_file) = if is_android {
        ("-buildmode=c-shared", "libgoreality.so")
    } else {
        ("-buildmode=c-archive", "libgoreality.a")
    };
    let lib_path = out_dir.join(lib_file);

    let mut cmd = Command::new("go");
    cmd.current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        // Self-resolve deps: `-mod=mod` lets `go build` fetch and record the
        // required modules (pinned in go.mod) instead of erroring on a missing
        // go.sum. GOTOOLCHAIN=auto downloads a newer Go if a dep ever demands
        // one. Keeps the feature buildable anywhere with Go + network, including
        // the main CI's `clippy --all-features` job.
        .env("GOFLAGS", "-mod=mod")
        .env("GOTOOLCHAIN", "auto")
        // Keep Go's caches inside OUT_DIR so the build works in cross/CI
        // containers where $HOME may be unset or read-only.
        .env("GOCACHE", out_dir.join("go-cache"))
        .env("GOPATH", out_dir.join("go-path"))
        .arg("build")
        .arg(buildmode)
        .arg("-o")
        .arg(&lib_path)
        .arg(".");
    if goarch == "arm" {
        cmd.env("GOARM", "7"); // armv7 (musleabihf)
    }
    // cgo's C compiler for the target. cross exports CC_<target>; cargo-ndk does
    // not, but its linker (CARGO_TARGET_<T>_LINKER) IS the NDK clang wrapper,
    // which doubles as the C compiler. Fall back to that, or cgo uses the host cc
    // and fails to assemble the target's runtime/cgo (e.g. gcc_arm64.S).
    let t_under = target.replace('-', "_");
    if let Ok(cc) = env::var(format!("CC_{target}"))
        .or_else(|_| env::var(format!("CC_{t_under}")))
        .or_else(|_| env::var(format!("CARGO_TARGET_{}_LINKER", t_under.to_uppercase())))
    {
        cmd.env("CC", cc);
    }

    let status = cmd
        .status()
        .expect("failed to run `go build` (is Go 1.24+ installed?)");
    assert!(status.success(), "go build of native/goreality failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    if is_android {
        // Dynamic link against libgoreality.so; it must ship in the same jniLibs
        // ABI dir as the app's own .so. Copy it up to target/<triple>/release/ so
        // the gradle `copyGorealitySo` step can pick it up per ABI.
        println!("cargo:rustc-link-lib=dylib=goreality");
        if let Some(triple_release) = out_dir.ancestors().nth(3) {
            let _ = std::fs::copy(&lib_path, triple_release.join(lib_file));
        }
    } else {
        println!("cargo:rustc-link-lib=static=goreality");
        // The Go runtime pulls in pthread/dl/resolv. glibc splits these into
        // their own libs; musl folds them into libc (and its static stubs would
        // clash with crt-static) — so only glibc needs the explicit links.
        if goos == "linux" && target.contains("gnu") {
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
            println!("cargo:rustc-link-lib=dylib=resolv");
        }
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
