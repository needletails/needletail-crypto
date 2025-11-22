//
//  NeedleTailCrypto+PublicKeyExportation.swift
//
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto

///MARK:  Private Public Key Exportation
extension NeedleTailCrypto {
    private func exportCurve25519PublicKey(_ publicKey: Curve25519.KeyAgreement.PublicKey) throws -> String {
        publicKey.encodedKey
    }
    
    private func exportP521PublicKey(_ publicKey: P521.KeyAgreement.PublicKey) throws -> String {
        publicKey.encodedKey
    }
    
    private func exportP384PublicKey(_ publicKey: P384.KeyAgreement.PublicKey) throws -> String {
        publicKey.encodedKey
    }
    
    private func exportP256PublicKey(_ publicKey: P256.KeyAgreement.PublicKey) throws -> String {
        publicKey.encodedKey
    }
}
