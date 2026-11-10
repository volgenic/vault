// The vault's macOS key protection: the only code in volgenic/vault that touches the Secure
// Enclave (threat model rule R30). Rust calls it through the C functions below.
//
// - The Secure Enclave key is a P-256 key-agreement key made by CryptoKit for this Mac only,
//   usable after the first unlock and with no fingerprint or password, so the vault works
//   unattended. CryptoKit hands back an opaque handle (`dataRepresentation`) that works only in
//   this Mac's Secure Enclave.
// - The vault key is wrapped to that key: an ephemeral P-256 key, ECDH, HKDF-SHA256, AES-GCM.
// - The shim never touches the Keychain: no Keychain item means no Keychain dialog, ever, for
//   any build (the owner's zero-prompt rule on the threat model page). Rust stores the handle
//   in root's folder and the wrapped key in the vault folder (src/keyprotect/macos.rs). Only
//   root calls `vkp_se_create` and `vkp_se_unwrap` (R14); `vkp_wrap` needs only the public key.
//
// Return codes: 0 ok, 1 output buffer too small, 2 Secure Enclave error, 6 bad input or crypto
// failure.

import CryptoKit
import Foundation
import Security

private let wrapInfo = Data("com.volgenic.vault/se-wrap/v1".utf8)
private let p256PublicLength = 65

private func copyOut(
    _ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    outLen.pointee = data.count
    if data.count > cap { return 1 }
    data.copyBytes(to: out, count: data.count)
    return 0
}

@_cdecl("vkp_se_available")
public func vkp_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

/// Makes a new Secure Enclave key. Writes its handle and its public key (65 bytes, X9.63).
@_cdecl("vkp_se_create")
public func vkp_se_create(
    _ handleOut: UnsafeMutablePointer<UInt8>, _ handleCap: Int, _ handleLen: UnsafeMutablePointer<Int>,
    _ pubOut: UnsafeMutablePointer<UInt8>, _ pubCap: Int, _ pubLen: UnsafeMutablePointer<Int>
) -> Int32 {
    var error: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
    else { return 2 }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let first = copyOut(key.dataRepresentation, handleOut, handleCap, handleLen)
        if first != 0 { return first }
        return copyOut(key.publicKey.x963Representation, pubOut, pubCap, pubLen)
    } catch {
        return 2
    }
}

private func wrapKey(ephemeralPublic: Data, sharedSecret: SharedSecret, recipientPublic: Data) -> SymmetricKey {
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: ephemeralPublic + recipientPublic, sharedInfo: wrapInfo,
        outputByteCount: 32)
}

/// Wraps `plain` to the Secure Enclave key's public half. Needs no Secure Enclave access.
/// Output: ephemeral public key (65 bytes) followed by AES-GCM nonce, ciphertext and tag.
@_cdecl("vkp_wrap")
public func vkp_wrap(
    _ pub: UnsafePointer<UInt8>, _ pubLen: Int, _ plain: UnsafePointer<UInt8>, _ plainLen: Int,
    _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    do {
        let recipientData = Data(bytes: pub, count: pubLen)
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: recipientData)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let key = wrapKey(ephemeralPublic: ephemeralPublic, sharedSecret: shared, recipientPublic: recipientData)
        let sealed = try AES.GCM.seal(Data(bytes: plain, count: plainLen), using: key)
        guard let combined = sealed.combined else { return 6 }
        return copyOut(ephemeralPublic + combined, out, cap, outLen)
    } catch {
        return 6
    }
}

/// Unwraps what `vkp_wrap` produced, using the Secure Enclave key behind `handle`.
@_cdecl("vkp_se_unwrap")
public func vkp_se_unwrap(
    _ handle: UnsafePointer<UInt8>, _ handleLen: Int, _ wrapped: UnsafePointer<UInt8>, _ wrappedLen: Int,
    _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if wrappedLen <= p256PublicLength { return 6 }
    let wrappedData = Data(bytes: wrapped, count: wrappedLen)
    let ephemeralPublic = wrappedData.prefix(p256PublicLength)
    let body = wrappedData.dropFirst(p256PublicLength)
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: handle, count: handleLen))
    } catch {
        return 2
    }
    do {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        let shared = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = wrapKey(
            ephemeralPublic: Data(ephemeralPublic), sharedSecret: shared,
            recipientPublic: key.publicKey.x963Representation)
        let box = try AES.GCM.SealedBox(combined: body)
        var plain = try AES.GCM.open(box, using: symmetric)
        let result = copyOut(plain, out, cap, outLen)
        plain.resetBytes(in: 0..<plain.count)
        return result
    } catch {
        return 6
    }
}
