//
//  NeedleTailCrypto+KeyGeneration.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto
import SwiftKyber

///MARK: Public private key generation
extension NeedleTailCrypto {
    public func generateCurve25519PrivateKey() -> Curve25519PrivateKey {
        Curve25519PrivateKey()
    }
    
    public func generateCurve25519SigningPrivateKey() -> Curve25519SigningPrivateKey {
        Curve25519.Signing.PrivateKey()
    }
    
    public func generateP521PrivateKey() -> P521PrivateKey {
        P521.KeyAgreement.PrivateKey()
    }
    
    public func generateP521PrivateSigningKey() -> P521PrivateSigningKey {
        P521.Signing.PrivateKey()
    }

    
    public func generateP384PrivateKey() -> P384PrivateKey {
        P384.KeyAgreement.PrivateKey()
    }
    
    public func generateP384PrivateSigningKey() -> P384PrivateSigningKey {
        P384.Signing.PrivateKey()
    }
    
    public func generateP256PrivateKey() -> P256PrivateKey {
        P256.KeyAgreement.PrivateKey()
    }
    
    public func generateP256PrivateSigningKey() -> P256PrivateSigningKey {
        P256.Signing.PrivateKey()
    }
    
    public func generateKyber1024PrivateSigningKey() throws -> Kyber1024.KeyAgreement.PrivateKey {
        try Kyber1024.KeyAgreement.PrivateKey()
    }
    
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    public func generateSecureEnclavePrivateKey() throws -> EnclavePrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
#endif
}
