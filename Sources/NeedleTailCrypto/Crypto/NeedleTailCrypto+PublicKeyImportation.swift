//
//  NeedleTailCrypto+PublicKeyImportation.swift
//
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto

extension NeedleTailCrypto {
    internal func importCurve25519PublicKey(_ publicKey: String) throws -> Curve25519.KeyAgreement.PublicKey {
        try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey.dataRepresentation)
    }
    
    internal func importP521PublicKey(_ publicKey: String) throws -> P521.KeyAgreement.PublicKey {
        try P521.KeyAgreement.PublicKey(rawRepresentation: publicKey.dataRepresentation)
    }
    
    internal func importP384PublicKey(_ publicKey: String) throws -> P384.KeyAgreement.PublicKey {
        try P384.KeyAgreement.PublicKey(rawRepresentation: publicKey.dataRepresentation)
    }
    
    internal func importP256PublicKey(_ publicKey: String) throws -> P256.KeyAgreement.PublicKey {
        try P256.KeyAgreement.PublicKey(rawRepresentation: publicKey.dataRepresentation)
    }
}
