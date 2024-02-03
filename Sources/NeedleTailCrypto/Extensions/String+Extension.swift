//
//  File.swift
//  
//
//  Created by Cole M on 1/24/24.
//

import Crypto
import Foundation

extension String {
    var dataRepresentation: Data {
        if let base64PublicKey = self.removingPercentEncoding {
            if let data = Data(base64Encoded: base64PublicKey) {
                return data
            }
        }
        fatalError("Data Representation must have a valid Public Key")
    }
    
    func derivedCurve25519SymmetricKey(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        if let salt = self.data(using: .utf8) {
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
        }
        fatalError("Could Not Derive Data from Salt")
    }
    
    func derivedP521SymmetricKey(
        privateKey: P521.KeyAgreement.PrivateKey,
        publicKey: P521.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        if let salt = self.data(using: .utf8) {
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
        }
        fatalError("Could Not Derive Data from Salt")
    }
    
    func derivedP384SymmetricKey(
        privateKey: P384.KeyAgreement.PrivateKey,
        publicKey: P384.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        if let salt = self.data(using: .utf8) {
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
        }
        fatalError("Could Not Derive Data from Salt")
    }
    
    func derivedP256SymmetricKey(
        privateKey: P256.KeyAgreement.PrivateKey,
        publicKey: P256.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        if let salt = self.data(using: .utf8) {
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
        }
        fatalError("Could Not Derive Data from Salt")
    }
    
    func derivedSecureEnclaveSymmetricKey(
        privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
        publicKey: P256.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        if let salt = self.data(using: .utf8) {
            return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
        }
        fatalError("Could Not Derive Data from Salt")
    }
}
