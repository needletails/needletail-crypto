//
//  NeedleTailCrypto+PrivateKeyExportation.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto


///MARK: Public private key exportation
extension NeedleTailCrypto {
    public func exportCurve25519PrivateKey(_ privateKey: Curve25519PrivateKey) throws -> String {
        privateKey.encodedKey
    }
    
    public func exportP521PrivateKey(_ privateKey: P521.KeyAgreement.PrivateKey) throws -> String {
        privateKey.encodedKey
    }
    
    public func exportP384PrivateKey(_ privateKey: P384.KeyAgreement.PrivateKey) throws -> String {
        privateKey.encodedKey
    }
    
    public func exportP256PrivateKey(_ privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
        privateKey.encodedKey
    }
    
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    public func exportSecureEnclavePrivateKey(_ privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey) throws -> String {
        privateKey.encodedKey
    }
#endif
}
