// The vault's two calls into Apple's Swift-only frameworks (#7689), behind a C interface that
// `src/keyprotect/enclave.rs` and `src/presence.rs` call. build.rs compiles this file into a
// static library on a Mac; nothing else in the vault is Swift.
//
// - The Secure Enclave (CryptoKit): the vault key, wrapped by a P-256 key that lives in this
//   Mac's Enclave and can't leave it. CryptoKit's Enclave keys need no Keychain item and no
//   entitlement: the Enclave hands back its key as an encrypted blob (`dataRepresentation`) that
//   only this Mac's Enclave can use, and the vault keeps that blob in its own file. The key's
//   access control is `privateKeyUsage` alone, so using it never asks for a fingerprint or a
//   password: the daemon unwraps at every start, unattended.
// - LocalAuthentication: Touch ID, or the login password, for the person's own sensitive acts.
//
// Buffers are the caller's: a key comes in and goes out through memory the Rust side wipes, and
// every Data this file makes from a key is zeroed before it is dropped (best effort: CryptoKit's
// own copies are its own).

import CryptoKit
import Dispatch
import Foundation
import LocalAuthentication
import Security

// Results, mirrored in Rust.
private let ok: Int32 = 0
private let unavailable: Int32 = 1
private let failed: Int32 = 2
private let declined: Int32 = 3
private let badInput: Int32 = 4

/// What a wrapped file starts with: `VSE2` now, `VSE1` before the seal was bound to its vault.
/// The seal's associated data is the caller's (`VSE2` and the vault's id; `VSE1` alone for a
/// legacy file), so a wrapped key moved to another vault doesn't open.
private let magic = Data("VSE2".utf8)
private let legacyMagic = Data("VSE1".utf8)
private let info = Data("volgenic-vault.key enclave v1".utf8)

private func wipe(_ data: inout Data) {
    data.resetBytes(in: 0..<data.count)
}

/// Whether this Mac has a Secure Enclave CryptoKit can use: 1 or 0.
@_cdecl("vault_se_available")
public func vaultSeAvailable() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

/// The symmetric key that seals the vault key: HKDF-SHA256 over the ECDH of the Enclave key and
/// a one-time software key, salted with both public keys.
private func sealingKey(_ shared: SharedSecret, _ ephemeral: Data, _ enclave: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral + enclave, sharedInfo: info, outputByteCount: 32)
}

/// Makes a new Enclave key and wraps `key` (32 bytes) with it, bound to `aad`, into `out`:
/// "VSE2", the Enclave blob's length (2 bytes, big-endian), the blob, the one-time public key
/// (65 bytes, X9.63) and AES-GCM's nonce, ciphertext and tag (60 bytes).
@_cdecl("vault_se_wrap")
public func vaultSeWrap(
    _ key: UnsafePointer<UInt8>, _ keyLen: Int, _ aad: UnsafePointer<UInt8>, _ aadLen: Int,
    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int, _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard keyLen == 32, aadLen > 0 else { return badInput }
    let bound = Data(bytes: aad, count: aadLen)
    guard SecureEnclave.isAvailable else { return unavailable }
    // Usable after the first unlock since boot, on this Mac only, with no user presence: the
    // daemon can come back while the screen is locked, and a backup can't carry it elsewhere.
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil)
    else { return failed }
    do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclave.publicKey)
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let sealing = sealingKey(shared, ephemeralPublic, enclave.publicKey.x963Representation)
        var plain = Data(bytes: key, count: keyLen)
        defer { wipe(&plain) }
        let box = try AES.GCM.seal(plain, using: sealing, authenticating: bound)
        guard let combined = box.combined else { return failed }
        let blob = enclave.dataRepresentation
        guard blob.count <= 0xFFFF else { return failed }
        var file = magic
        file.append(UInt8(blob.count >> 8))
        file.append(UInt8(blob.count & 0xFF))
        file.append(blob)
        file.append(ephemeralPublic)
        file.append(combined)
        guard file.count <= outCap else { return badInput }
        file.copyBytes(to: out, count: file.count)
        outLen.pointee = file.count
        return ok
    } catch {
        return failed
    }
}

/// Unwraps a file `vault_se_wrap` wrote, bound to `aad`, with this Mac's Enclave, into `out`
/// (32 bytes).
@_cdecl("vault_se_unwrap")
public func vaultSeUnwrap(
    _ wrapped: UnsafePointer<UInt8>, _ wrappedLen: Int, _ aad: UnsafePointer<UInt8>, _ aadLen: Int,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let file = Data(bytes: wrapped, count: wrappedLen)
    guard aadLen > 0, file.count > 6, file.prefix(4) == magic || file.prefix(4) == legacyMagic else { return badInput }
    let bound = Data(bytes: aad, count: aadLen)
    let blobLen = Int(file[4]) << 8 | Int(file[5])
    let ephemeralAt = 6 + blobLen
    let boxAt = ephemeralAt + 65
    guard file.count == boxAt + 60 else { return badInput }
    guard SecureEnclave.isAvailable else { return unavailable }
    do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: file.subdata(in: 6..<ephemeralAt))
        let ephemeralPublic = file.subdata(in: ephemeralAt..<boxAt)
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        let shared = try enclave.sharedSecretFromKeyAgreement(with: ephemeral)
        let sealing = sealingKey(shared, ephemeralPublic, enclave.publicKey.x963Representation)
        let box = try AES.GCM.SealedBox(combined: file.subdata(in: boxAt..<file.count))
        var plain = try AES.GCM.open(box, using: sealing, authenticating: bound)
        defer { wipe(&plain) }
        guard plain.count == 32 else { return failed }
        plain.copyBytes(to: out, count: 32)
        return ok
    } catch {
        return failed
    }
}

/// The answer of one LocalAuthentication check, handed from its callback to the waiting thread.
private final class Answer: @unchecked Sendable {
    var passed = false
}

/// Asks the person at this Mac to confirm with Touch ID, or their login password when Touch ID
/// isn't set up or they choose it, giving `reason` ("… is trying to <reason>"). Waits for the
/// answer, at most `seconds`: 0 passed, 1 no way to ask here, 3 declined, cancelled or timed out.
@_cdecl("vault_la_confirm")
public func vaultLaConfirm(_ reason: UnsafePointer<CChar>, _ seconds: Int32) -> Int32 {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return unavailable }
    let answer = Answer()
    let done = DispatchSemaphore(value: 0)
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(cString: reason)) { passed, _ in
        answer.passed = passed
        done.signal()
    }
    if done.wait(timeout: .now() + .seconds(Int(seconds))) == .timedOut {
        context.invalidate()
        return declined
    }
    return answer.passed ? ok : declined
}
