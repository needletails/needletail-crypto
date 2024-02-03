//
//  NeedleTailCrypto+KeyGeneration.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto


///MARK: Public private key generation
extension NeedleTailCrypto {
    public func generateCurve25519PrivateKey() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }
    
    public func generateP521PrivateKey() -> P521.KeyAgreement.PrivateKey {
        P521.KeyAgreement.PrivateKey()
    }
    
    public func generateP384PrivateKey() -> P384.KeyAgreement.PrivateKey {
        P384.KeyAgreement.PrivateKey()
    }
    
    public func generateP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
        P256.KeyAgreement.PrivateKey()
    }
    
    public func generateSecureEnclavePrivateKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
}
