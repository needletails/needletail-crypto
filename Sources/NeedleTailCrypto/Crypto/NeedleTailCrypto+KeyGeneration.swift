//
//  NeedleTailCrypto+KeyGeneration.swift
//
//
//  Created by Cole M on 1/24/24.
//
import Foundation
@_exported import Crypto

///MARK: Public private key generation
extension NeedleTailCrypto {
    public func generateCurve25519PrivateKey() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }
    
    public func generateCurve25519SigningPrivateKey() -> Curve25519.Signing.PrivateKey {
        Curve25519.Signing.PrivateKey()
    }
    
    public func generateP521PrivateKey() -> P521.KeyAgreement.PrivateKey {
        P521.KeyAgreement.PrivateKey()
    }
    
    public func generateP521PrivateSigningKey() -> P521.Signing.PrivateKey {
        P521.Signing.PrivateKey()
    }
    
    
    public func generateP384PrivateKey() -> P384.KeyAgreement.PrivateKey {
        P384.KeyAgreement.PrivateKey()
    }
    
    public func generateP384PrivateSigningKey() -> P384.Signing.PrivateKey {
        P384.Signing.PrivateKey()
    }
    
    public func generateP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
        P256.KeyAgreement.PrivateKey()
    }
    
    public func generateP256PrivateSigningKey() -> P256.Signing.PrivateKey {
        P256.Signing.PrivateKey()
    }
    
    public func generateMLKem1024PrivateKey() throws -> MLKEM1024.PrivateKey {
        try MLKEM1024.PrivateKey()
    }
}

extension MLKEM1024.PrivateKey: @retroactive Codable {
   
    private enum CodingKeys: String, CodingKey {
        case integrityCheckedRepresentation
        case seedRepresentation
        case publicKey
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(integrityCheckedRepresentation, forKey: .integrityCheckedRepresentation)
        try container.encode(seedRepresentation, forKey: .seedRepresentation)
        try container.encode(publicKey, forKey: .publicKey)
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        // If we encoded integrityCheckedRepresentation, use it
        if container.contains(.integrityCheckedRepresentation) {
            let integrity = try container.decode(Data.self, forKey: .integrityCheckedRepresentation)
            try self.init(integrityCheckedRepresentation: integrity)
            return
        }
        
        // Fallback: seed + publicKey
        let seed = try container.decode(Data.self, forKey: .seedRepresentation)
        let publicKey = try container.decode(MLKEM1024.PublicKey.self, forKey: .publicKey)
        try self.init(seedRepresentation: seed, publicKey: publicKey)
    }
}

extension MLKEM1024.PublicKey: @retroactive Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawRepresentation)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(Data.self)
        try self.init(rawRepresentation: raw)
    }
}
