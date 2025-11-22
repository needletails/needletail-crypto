//
//  NeedleTailCrypto+DerivedSymmentricKeys.swift
//
//
//  Created by Cole M on 1/24/24.
//
import Foundation
@_exported import Crypto

//MARK: Public
extension NeedleTailCrypto {
    
    /// A hash basaed approach to generate a *SymmetricKey*
    /// - Parameter key: A string we can use as a key to generate a SymmetricKey it should be unique to a client/app
    /// - Returns: Our *SymmetricKey*
    public func userInfoKey(_ key: String) throws -> SymmetricKey {
        guard let keyData = key.data(using: .utf8) else { throw Errors.keyDataNil }
        return try symmetricKey(from: keyData)
    }
    
    public func symmetricKey(from data: Data) throws -> SymmetricKey {
        let hash = SHA256.hash(data: data)
        let hashString = hash.map { String(format: "%02hhx", $0)}.joined()
        let subString = String(hashString.prefix(32))
        guard let symmetricKeyData = subString.data(using: .utf8) else { throw Errors.symmetricKeyDataNil }
        return SymmetricKey(data: symmetricKeyData)
    }
    
    /// This method is used to generate a *SymmetricKey* from A users PrivateKey/PublicKey per their desire Crypto Algorythm. The salt is used for key derivation. The private key is used to create a shared secret between two users for an End-to-End Encrypted message.The shared secret inturn creates a Symmetric key used to unlock message using hkdf. The hashing algorythm is *SHA256* based.
    /// - Parameters:
    ///   - salt: "A unique salt string used for communication between end users"
    ///   - userPrivateKey: The inital users private key
    ///   - publicKey: The other parties public key
    ///   - cryptoAlogrythm: the destire crypto algorythm to use.
    /// - Returns: The *SymmetricKey*
    public func derivedKeyLogic(
        salt: String,
        cryptoAlogrythm: CryptoAlogrythm,
        sharedSecret: SharedSecret
    ) throws -> SymmetricKey {
            return try derivedSymmetricKey(
                sharedSecret: sharedSecret,
                salt: salt.dataRepresentation)
        }
    
    ///  derives our ke
    /// - Parameters:
    ///   - sharedSecret: Generated from our localPrivateKey and remotesPublicKey
    ///   - algorithm:  The alorgithm to use along with the current localPrivateKey and remotePublicKey
    public func deriveHKDFSymmetricKey<Hash: HashFunction & Sendable>(
        hash: Hash.Type,
        from sharedSecret: SharedSecret,
        with symmetricKey: SymmetricKey,
        sharedInfo: Data
    ) async throws -> SymmetricKey {
        try deriveHKDFSymmetricKey(
            hash: Hash.self,
            secret: sharedSecret,
            symmetricKey: symmetricKey,
            sharedInfo: sharedInfo
        )
    }
}

//MARK: Private
extension NeedleTailCrypto {
    
    /// A double ratchet root key is based of of the remote public key  and our shared secret
    private func deriveHKDFSymmetricKey<Hash: HashFunction & Sendable>(
        hash of: Hash.Type,
        secret: SharedSecret,
        symmetricKey: SymmetricKey,
        sharedInfo: Data
    ) throws -> SymmetricKey {
        return secret.hkdfDerivedSymmetricKey(
            using: Hash.self,
            salt: symmetricKey.withUnsafeBytes { buffer in
                Data(buffer: buffer.bindMemory(to: UInt8.self))
            },
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
    }
}
