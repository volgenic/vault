// The vault's macOS key protection: the only code in volgenic/vault that touches the Secure
// Enclave or the Keychain (threat model rule R30). Rust calls it through the C functions below.
//
// - The Secure Enclave key is a P-256 key-agreement key made by CryptoKit for this Mac only,
//   usable after the first unlock and with no fingerprint or password, so the vault works
//   unattended. CryptoKit hands back an opaque handle (`dataRepresentation`) that works only in
//   this Mac's Secure Enclave.
// - The vault key is wrapped to that key: an ephemeral P-256 key, ECDH, HKDF-SHA256, AES-GCM.
// - The handle, the public key and the wrapped vault key live in one generic-password item,
//   service "com.volgenic.vault", in the login keychain. The item is created by the vault
//   itself, so its access list trusts the vault build that created it (R14).
//
// Return codes: 0 ok, 1 output buffer too small, 2 Secure Enclave error, 3 item already exists,
// 4 item not found, 5 other Keychain error, 6 bad input or crypto failure.

import CryptoKit
import Foundation
import Security

private let itemService = "com.volgenic.vault"
private let itemAccount = "vault-key"
private let itemLabel = "com.volgenic.vault"
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

private func baseQuery() -> [String: Any] {
    // No kSecUseDataProtectionKeychain: that keychain needs an entitlement a command-line
    // program can't carry, so this is the login keychain (file-based), as R14 intends.
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: itemService,
        kSecAttrAccount as String: itemAccount,
    ]
}

/// Stores the key-protection record. Fails with 3 if the item already exists.
@_cdecl("vkp_kc_put")
public func vkp_kc_put(_ data: UnsafePointer<UInt8>, _ len: Int) -> Int32 {
    var query = baseQuery()
    query[kSecAttrLabel as String] = itemLabel
    query[kSecAttrDescription as String] = "Volgenic vault key, wrapped by the Secure Enclave"
    query[kSecValueData as String] = Data(bytes: data, count: len)
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecSuccess { return 0 }
    if status == errSecDuplicateItem { return 3 }
    return 5
}

/// Reads the key-protection record.
@_cdecl("vkp_kc_get")
public func vkp_kc_get(
    _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    var query = baseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return 4 }
    guard status == errSecSuccess, let data = result as? Data else { return 5 }
    return copyOut(data, out, cap, outLen)
}

/// Says whether the item exists, reading its attributes only (no secret data, so no prompt).
/// Returns 1 if it exists, 0 if not, negative on error.
@_cdecl("vkp_kc_exists")
public func vkp_kc_exists() -> Int32 {
    var query = baseQuery()
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess { return 1 }
    if status == errSecItemNotFound { return 0 }
    return -1
}

/// Deletes the item.
@_cdecl("vkp_kc_delete")
public func vkp_kc_delete() -> Int32 {
    let status = SecItemDelete(baseQuery() as CFDictionary)
    if status == errSecSuccess { return 0 }
    if status == errSecItemNotFound { return 4 }
    return 5
}
