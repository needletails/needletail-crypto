//
//  NeedleTailCrypto+PasswordKDF.swift
//  needletail-crypto
//
//  Password-based key derivation for at-rest keys. `deriveStrictSymmetricKey`
//  (kept for compatibility) is a single HKDF over the password that ignores its
//  salt; it offers no work factor and no per-device separation. This derivation
//  is PBKDF2-HMAC-SHA512 (RFC 8018) over the real salt.
//

import Crypto
import Foundation

extension NeedleTailCrypto {
    /// PBKDF2-HMAC-SHA512 with a 32-byte output.
    ///
    /// - Parameters:
    ///   - password: UTF-8 password bytes.
    ///   - salt: Random per-device salt; different salts give unrelated keys.
    ///   - iterations: Work factor. Callers pick it by deployment; the output is
    ///     stable for a given (password, salt, iterations).
    public func derivePasswordSymmetricKey(
        password: Data,
        salt: Data,
        iterations: Int
    ) -> SymmetricKey {
        precondition(iterations >= 1, "PBKDF2 requires at least one iteration")
        let key = SymmetricKey(data: password)
        // dkLen == hLen for SHA-512 → exactly one block, INT(1) big-endian.
        var block = salt
        block.append(contentsOf: [0, 0, 0, 1])
        var u = Data(HMAC<SHA512>.authenticationCode(for: block, using: key))
        var t = u
        for _ in 1..<iterations {
            u = Data(HMAC<SHA512>.authenticationCode(for: u, using: key))
            for index in t.indices {
                t[index] ^= u[index]
            }
        }
        return SymmetricKey(data: t.prefix(32))
    }
}
