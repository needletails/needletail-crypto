//
//  NeedleTailCrypto+SecureEnclave.swift
//
//
//  Created by Cole M on 1/25/24.
//

@_exported import Crypto

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
#if canImport(CryptoKit)
import CryptoKit
#endif

public typealias EnclavePrivateKey = SecureEnclave.P256.KeyAgreement.PrivateKey

extension NeedleTailCrypto {
    /// Fetches our P256 Private Key from the secure enclave.
    /// - Returns: The *Secure Enclave*'s P256 Private Key
    public func getSecureEnclavePrivateKey(configuration: KeychainConfiguration) async throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        return try await secureEnclave.fetchPrivateKey(configuration: configuration)
    }
    
    /// This is a helper method that was the consumer does not need to intitialize a Secure Enclave object on their own. If a Service Account is not specified in the *NeedleTailCrypto* Object, a service account will be automatically created for you. Multiple Keys Can be saved per secure enclave instance. Each instance will have it's own service account. Additional Secure Enclave instances will need to be created manually and the other the ``generateSecureEnclavePrivateKey()`` method must be used in conjunction with it to derive the private key.
    public func saveSecureEnclavePrivateKey(configuration: KeychainConfiguration) async throws {
        let key = try generateSecureEnclavePrivateKey()
        try await secureEnclave.savePrivateKey(configuration: configuration, key: key)
    }
    
    
    public func importSecureEnclavePrivateKey(_ privateKey: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: privateKey.dataRepresentation)
    }
    
    public func exportSecureEnclavePrivateKey(_ privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey) throws -> String {
        privateKey.encodedKey
    }
    
    public func generateSecureEnclavePrivateKey() throws -> EnclavePrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.dataRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? privateKeyBase64
    }
}
#endif
