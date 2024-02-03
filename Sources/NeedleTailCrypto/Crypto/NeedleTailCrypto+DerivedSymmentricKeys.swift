//
//  NeedleTailCrypto+DerivedSymmentricKeys.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto

//MARK: Public
extension NeedleTailCrypto {
    
    /// A hash basaed approach to generate a *SymmetricKey*
    /// - Parameter key: A string we can use as a key to generate a SymmetricKey it should be unique to a client/app
    /// - Returns: Our *SymmetricKey*
    public func userInfoKey(_ key: String) throws -> SymmetricKey {
        guard let keyData = key.data(using: .utf8) else { throw Errors.keyDataNil }
        let hash = SHA256.hash(data: keyData)
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
        userPrivateKey: String,
        publicKey: String,
        cryptoAlogrythm: CryptoAlogrythm
    ) throws -> SymmetricKey {
        switch cryptoAlogrythm {
        case .curve25519:
            return try deriveCurve25519SymmetricKey(
                salt: salt,
                privateKey: try importCurve25519PrivateKey(userPrivateKey),
                publicKey: try importCurve25519PublicKey(publicKey)
            )
        case .p256:
            return try deriveP256SymmetricKey(
                salt: salt,
                privateKey: try importP256PrivateKey(userPrivateKey),
                publicKey: try importP256PublicKey(publicKey)
            )
        case .p384:
            return try deriveP384SymmetricKey(
                salt: salt,
                privateKey: try importP384PrivateKey(userPrivateKey),
                publicKey: try importP384PublicKey(publicKey)
            )
        case .p521:
            return try deriveP521SymmetricKey(
                salt: salt,
                privateKey: try importP521PrivateKey(userPrivateKey),
                publicKey: try importP521PublicKey(publicKey)
            )
        case .secureEnclave:
            return try deriveSecureEnclaveSymmetricKey(
                salt: salt,
                privateKey: try importSecureEnclavePrivateKey(userPrivateKey),
                publicKey: try importP256PublicKey(publicKey)
            )
        }
    }
}


//MARK: Private
extension NeedleTailCrypto {
    private func deriveCurve25519SymmetricKey(
        salt: String,
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        return try salt.derivedCurve25519SymmetricKey(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    private func deriveP521SymmetricKey(
        salt: String,
        privateKey: P521.KeyAgreement.PrivateKey,
        publicKey: P521.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        return try salt.derivedP521SymmetricKey(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    private func deriveP384SymmetricKey(
        salt: String,
        privateKey: P384.KeyAgreement.PrivateKey,
        publicKey: P384.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        return try salt.derivedP384SymmetricKey(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    private func deriveP256SymmetricKey(
        salt: String,
        privateKey: P256.KeyAgreement.PrivateKey,
        publicKey: P256.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        return try salt.derivedP256SymmetricKey(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    private func deriveSecureEnclaveSymmetricKey(
        salt: String,
        privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
        publicKey: P256.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        return try salt.derivedSecureEnclaveSymmetricKey(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
}
