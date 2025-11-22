//
//  NeedleTailCrypto+PrivateKeyExportation.swift
//
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto


///MARK: Public private key exportation
extension NeedleTailCrypto {
    public func exportCurve25519PrivateKey(_ privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> String {
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
}
