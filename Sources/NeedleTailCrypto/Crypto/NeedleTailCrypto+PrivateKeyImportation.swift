//
//  NeedleTailCrypto+PrivateKeyImportation.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto

///MARK: Public private key importation
extension NeedleTailCrypto {
    public func importCurve25519PrivateKey(_ privateKey: String) throws -> Curve25519PrivateKey {
        try Curve25519PrivateKey(rawRepresentation: privateKey.dataRepresentation)
    }
    
    public func importP521PrivateKey(_ privateKey: String) throws -> P521.KeyAgreement.PrivateKey {
        try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKey.dataRepresentation)
    }
    
    public func importP384PrivateKey(_ privateKey: String) throws -> P384.KeyAgreement.PrivateKey {
        try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKey.dataRepresentation)
    }
    
    public func importP256PrivateKey(_ privateKey: String) throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey.dataRepresentation)
    }
    
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    public func importSecureEnclavePrivateKey(_ privateKey: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: privateKey.dataRepresentation)
    }
#endif
}
