// Builds the macOS key-protection shim (src/keyprotect/macos.swift) into a static library.
// It is the only code that touches the Keychain and the Secure Enclave (rule R30 on the
// threat model page). Other platforms get no shim and a stub module instead.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/keyprotect/macos.swift");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        Ok(other) => panic!("unsupported macOS architecture {other}"),
        Err(_) => panic!("no target architecture"),
    };
    let lib = out.join("libvaultkeyprotect.a");
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-O",
            "-module-name",
            "VaultKeyProtect",
            "-target",
            &format!("{arch}-apple-macos13.0"),
            "src/keyprotect/macos.swift",
            "-o",
        ])
        .arg(&lib)
        .status()
        .expect("run xcrun swiftc (install Xcode or the Command Line Tools)");
    assert!(status.success(), "swiftc failed to build the key-protection shim");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=vaultkeyprotect");
    for framework in ["Foundation", "Security", "CryptoKit"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    // The Swift runtime ships with macOS; the toolchain folder holds its compatibility shims.
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    if let Ok(found) = Command::new("xcrun").args(["--find", "swiftc"]).output() {
        let swiftc = PathBuf::from(String::from_utf8_lossy(&found.stdout).trim());
        if let Some(toolchain_usr) = swiftc.parent().and_then(|bin| bin.parent()) {
            let compat = toolchain_usr.join("lib/swift/macosx");
            println!("cargo:rustc-link-search=native={}", compat.display());
        }
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=13.0");
}
