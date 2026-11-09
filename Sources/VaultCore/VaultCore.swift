/// The vault's platform-neutral core. Keep it free of Apple-only imports (Security, CryptoKit's
/// Secure Enclave, Foundation APIs Linux lacks) so it builds on Linux later; Keychain and Secure
/// Enclave code goes in a target of its own.
public enum VaultCore {
    public static let version = "0.0.0"
}
