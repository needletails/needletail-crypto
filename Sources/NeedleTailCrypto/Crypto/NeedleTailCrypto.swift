//
//  NeedleTailCrypto.swift
//  Cartisim
//
//  Created by Cole M on 11/14/20.
//  Copyright © 2020 Cole M. All rights reserved.
//

import Foundation
@_exported import Crypto

/// Our Crypto Module. NeedleTailCrypto is designed as a wrapper around common *SwiftCrypto*/*CryptoKit* code. It is designed to simply Encrypting and decrypting your data to be stored or sent else where. Our goal in
/// this Swift Package is to make it easier for  not only encryption, but where public/private keys could and or should be stored.
public struct NeedleTailCrypto: Sendable {
    
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let secureEnclave = NTSecureEnclave()
#endif
    
    public let keychain = NTKeychain()
    
    public init() {}
    
    /// Errors
    public enum Errors: Error {
        case keyDataNil
        case symmetricKeyDataNil
        case combinedDataNil
        case decryptionError
        case secureEnclaveKeychainMismatch
        case invalidBase64Encoding
        case invalidUTF8Encoding
    }
    
    /// The desired algorythm you intend to use for deriving key logic
    public enum CryptoAlogrythm: Sendable {
        case curve25519(SymmetricKey),
             p256(SymmetricKey),
             p384(SymmetricKey),
             p521(SymmetricKey)
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
        case secureEnclave(SymmetricKey)
#endif
    }
}

///MARK:  Simple Encryption/Decryption
extension NeedleTailCrypto {
    
    /// Use this method to encrypt *Foundation*'s Data object type
    /// - Parameters:
    ///   - data: Foundation Data to encrypt
    ///   - symmetricKey: The *SymmetricKey* that you derive from the ``derivedKeyLogic()`` method. Alternatively you may derive a *SymmetricKey* from the ``userInfoKey()`` method for a *SHA256 * Hash based  *SymmetricKey*.
    /// - Returns: Your encrypted data
    public func encrypt(data: Data, symmetricKey: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> Data? {
        let encrypted = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)
        return encrypted.combined
    }
    
    /// Use this method to decrypt *Foundation*'s Data object type
    /// - Parameters:
    ///   - data: Foundation data to decrypt
    ///   - symmetricKey: The *SymmetricKey* that you derive from the ``derivedKeyLogic()`` method. Alternatively you may derive a *SymmetricKey* from the ``userInfoKey()`` method for a *SHA256 * Hash based  *SymmetricKey*.
    /// - Returns: Your decrypted data
    public func decrypt(data: Data, symmetricKey: SymmetricKey) throws -> Data? {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    /// Use this method to encrypt *Foundation*'s String object type
    /// - Parameters:
    ///   - text: A Foundation String to encrypt
    ///   - symmetricKey: The *SymmetricKey* that you derive from the ``derivedKeyLogic()`` method. Alternatively you may derive a *SymmetricKey* from the ``userInfoKey()`` method for a *SHA256 * Hash based  *SymmetricKey*.
    /// - Returns: Your encrypted String
    /// - Throws: ``Errors/invalidUTF8Encoding`` if the string cannot be encoded as UTF-8, ``Errors/combinedDataNil`` if encryption fails
    public func encryptText(text: String, symmetricKey: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> String {
        guard let textData = text.data(using: .utf8) else {
            throw Errors.invalidUTF8Encoding
        }
        guard let encrypted = try AES.GCM.seal(textData, using: symmetricKey, nonce: nonce).combined else {
            throw Errors.combinedDataNil
        }
        return encrypted.base64EncodedString()
    }
    
    /// Use this method to decrypt *Foundation*'s String object type
    /// - Parameters:
    ///   - text: A Foundation String to decrypt
    ///   - symmetricKey: The *SymmetricKey* that you derive from the ``derivedKeyLogic()`` method. Alternatively you may derive a *SymmetricKey* from the ``userInfoKey()`` method for a *SHA256 * Hash based  *SymmetricKey*.
    /// - Returns: Your decrypted String
    /// - Throws: ``Errors/invalidBase64Encoding`` if the text is not valid base64, ``Errors/invalidUTF8Encoding`` if decrypted data cannot be decoded as UTF-8, ``Errors/decryptionError`` if decryption fails
    public func decryptText(text: String, symmetricKey: SymmetricKey) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw Errors.invalidBase64Encoding
        }
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        guard let text = String(data: decryptedData, encoding: .utf8) else {
            throw Errors.invalidUTF8Encoding
        }
        return text
    }
}
