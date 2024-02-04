//
//  SecureEnclave.swift
//
//
//  Created by Cole M on 1/22/24.
//
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
import Crypto
import Foundation

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
public actor NTSecureEnclave {
    
    enum Errors: Error {
        case unexpectedAccessData, unhandledError(OSStatus)
    }
    
    private let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence, .biometryCurrentSet],
        nil
    )
    
    internal func fetchPrivateKey(configuration: KeychainConfiguration) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard let key = try loadPrivateKey(configuration: configuration) else {
                guard SecureEnclave.isAvailable else {
                    throw Errors.unexpectedAccessData
                }

                guard let accessControl = accessControl else {
                    throw Errors.unexpectedAccessData
                };

                let authContext = LAContext()

                let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authContext
                )

            try savePrivateKey(configuration: configuration, key: privateKey)

                return privateKey
            }

            return key
        }
    
    // MARK: Convenience
    private func keychainQuery(
        configuration: KeychainConfiguration,
        key: SecureEnclave.P256.KeyAgreement.PrivateKey? = nil,
        returnData: Bool = false
    ) -> [String: Any] {
        var query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain: true,
            kSecAttrSynchronizable: true
        ] as [String: Any]
        
        if let service = configuration.service {
            query[kSecAttrService as String] = service as Any
        }
        
        if let account = configuration.account {
            query[kSecAttrAccount as String] = account as Any
        }
        
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup as Any
        }
        if let data = key?.dataRepresentation {
            query[kSecValueData as String] = data as Any
        }
        if returnData {
            query[kSecReturnData as String] = returnData as Any
        }
        return query
    }
    
    internal func savePrivateKey(
        configuration: KeychainConfiguration,
        key: SecureEnclave.P256.KeyAgreement.PrivateKey
    ) throws {
            let query = keychainQuery(configuration: configuration, key: key)

            SecItemDelete(query as CFDictionary)

            let status = SecItemAdd(query as CFDictionary, nil)

            guard status == errSecSuccess else {
                throw Errors.unhandledError(status)
            }
        }

    private func loadPrivateKey(configuration: KeychainConfiguration) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        guard SecureEnclave.isAvailable else {
            throw Errors.unexpectedAccessData
        }
        
        let authContext = LAContext()
        let query = keychainQuery(configuration: configuration, returnData: true)
        var item: CFTypeRef?
        
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecItemNotFound:
            return nil
        case errSecSuccess:
            guard let data = item as? Data else {
                return nil
            }
            
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: data,
                authenticationContext: authContext
            )
        case let status:
            throw Errors.unhandledError(status)
        }
    }
}
#endif
