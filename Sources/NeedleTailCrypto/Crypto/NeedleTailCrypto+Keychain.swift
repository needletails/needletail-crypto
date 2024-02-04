//
//  NeedleTailCrypto+Keychain.swift
//
//
//  Created by Cole M on 1/25/24.
//

import Crypto


extension NeedleTailCrypto {
    
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    /// Fetches our P256 Private Key from the secure enclave.
    /// - Returns: The *Secure Enclave*'s P256 Private Key
    public func fetchKeychainItem(configuration: KeychainConfiguration) async throws -> String? {
        return try await keychain.fetchItem(configuration: configuration)
    }
    
    public func deleteKeychainItem(configuration: KeychainConfiguration) async throws {
        return try await keychain.deleteItem(configuration: configuration)
    }
    
    /// This is a helper method that was the consumer does not need to intitialize a Secure Enclave object on their own. If a Service Account is not specified in the *NeedleTailCrypto* Object, a service account will be automatically created for you. Multiple Keys Can be saved per secure enclave instance. Each instance will have it's own service account. Additional Secure Enclave instances will need to be created manually and the other the ``generateSecureEnclavePrivateKey()`` method must be used in conjunction with it to derive the private key.
    public func saveKeychainPrivateKey(configuration: KeychainConfiguration, with alogrythm: CryptoAlogrythm) async throws {
        var key = ""
        switch alogrythm {
        case .curve25519:
            key = generateCurve25519PrivateKey().encodedKey
        case .p256:
            key = generateP256PrivateKey().encodedKey
        case .p384:
            key = generateP384PrivateKey().encodedKey
        case .p521:
            key = generateP521PrivateKey().encodedKey
        case .secureEnclave:
            fatalError("Must use Secure Enclave object not Keychain Object")
        }
        try await keychain.save(item: key, with: configuration)
    }
    
    public func saveKeychain(item: String, configuration: KeychainConfiguration) async throws {
        try await keychain.save(item: item, with: configuration)
    }
#endif
}
