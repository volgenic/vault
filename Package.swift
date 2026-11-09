// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "vault",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "vault", targets: ["vault"]),
    ],
    targets: [
        // The platform-neutral core: decisions over plain values, no Apple-only imports.
        .target(name: "VaultCore"),
        // The command-line executable, a thin shell around VaultCore.
        .executableTarget(name: "vault", dependencies: ["VaultCore"]),
    ]
)
