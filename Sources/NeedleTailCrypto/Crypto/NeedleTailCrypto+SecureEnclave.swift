//
//  NeedleTailCrypto+SecureEnclave.swift
//
//
//  Created by Cole M on 1/25/24.
//

import Crypto

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
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
}
#endif
