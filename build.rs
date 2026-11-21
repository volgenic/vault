// Records the git commit the build came from and the target it is for, for `vault status` and
// `vault --version`. On a Mac, building for macOS, also compiles `src/macos/security.swift` (the
// Secure Enclave and Touch ID, #7689) into a static library the vault links.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A tool's standard output, or the build stops with what it said.
fn run(command: &mut Command, what: &str) -> String {
    let out = command.output().unwrap_or_else(|e| panic!("{what} didn't run: {e}"));
    if !out.status.success() {
        panic!("{what} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Compiles the Swift file and tells rustc how to link it and the Swift runtime (which macOS
/// ships in /usr/lib/swift). Only when the target is macOS and the build runs on a Mac: a
/// `cargo check --target aarch64-apple-darwin` from Linux links nothing, so it needs no Swift.
fn swift(target: &str) {
    println!("cargo:rerun-if-changed=src/macos/security.swift");
    // build.rs's own cfg is the machine it runs on.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") || !cfg!(target_os = "macos") {
        return;
    }
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let arch = if target.starts_with("aarch64") { "arm64" } else { "x86_64" };
    // CryptoKit's Secure Enclave keys and LocalAuthentication need macOS 11 at most; Rust's own
    // floor for aarch64-apple-darwin is 11.0 too.
    let swift_target = format!("{arch}-apple-macos11.0");
    let library = out_dir.join("libvault_security.a");
    run(
        Command::new("xcrun").args(["swiftc", "-emit-library", "-static", "-parse-as-library", "-O", "-swift-version", "5"]).args([
            "-target",
            &swift_target,
            "-module-name",
            "VaultSecurity",
            "-o",
        ])
        .arg(&library)
        .arg("src/macos/security.swift"),
        "swiftc",
    );
    // The toolchain's compatibility libraries (static) and the SDK's Swift runtime stubs.
    let swiftc = run(Command::new("xcrun").args(["--find", "swiftc"]), "xcrun --find swiftc");
    let toolchain = Path::new(&swiftc).parent().and_then(Path::parent).expect("the toolchain's folder");
    let sdk = run(Command::new("xcrun").args(["--show-sdk-path"]), "xcrun --show-sdk-path");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-search=native={}", toolchain.join("lib/swift/macosx").display());
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=vault_security");
    for framework in ["CryptoKit", "LocalAuthentication", "Foundation", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .is_some_and(|out| out.status.success() && !out.stdout.is_empty());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    swift(&target);
    println!("cargo:rustc-env=VAULT_TARGET={target}");
    println!("cargo:rustc-env=VAULT_GIT_COMMIT={commit}{}", if dirty { "-modified" } else { "" });
}
