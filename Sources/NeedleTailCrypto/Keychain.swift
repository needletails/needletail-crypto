
//  KeychainItem.swift
//
//  Created by Cole M on 6/8/20.
//  Copyright © 2020 Cole M. All rights reserved.

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Foundation

private struct KeychainItem: Sendable {

    // MARK: Keychain Access
    fileprivate func readItem(configuration: KeychainConfiguration) throws -> String {
        var query = keychainQuery(configuration: configuration)
        
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        
        switch status {
        case errSecItemNotFound:
            throw KeychainError.noPassword
        case noErr:
            guard let existingItem = queryResult as? [String: AnyObject],
                  let passwordData = existingItem[kSecValueData as String] as? Data,
                  let password = String(data: passwordData, encoding: .utf8) else {
                throw KeychainError.unexpectedPasswordData
            }
            return password
        default:
            throw KeychainError.unhandledError
        }
    }
    
    fileprivate func saveItem(_ item: String, with configuration: KeychainConfiguration) throws {
        guard let encodedItem = item.data(using: .utf8) else {
            throw KeychainError.unexpectedItemData
        }
        
        let query = keychainQuery(configuration: configuration)
        let status: OSStatus
        
        do {
            _ = try readItem(configuration: configuration)
            
            var attributesToUpdate = [String: Any]()
            attributesToUpdate[kSecValueData as String] = encodedItem
            
            status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        } catch KeychainError.noPassword {
            var newItem = query
            newItem[kSecValueData as String] = encodedItem
            
            status = SecItemAdd(newItem as CFDictionary, nil)
        }
        
        guard status == noErr else {
            throw KeychainError.unhandledError
        }
    }
    
    fileprivate func deleteItem(configuration: KeychainConfiguration) throws {
        let query = keychainQuery(configuration: configuration)
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError
        }
    }
    
    private func keychainQuery(configuration: KeychainConfiguration) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: true
        ]
        
        if let service = configuration.service {
            query[kSecAttrService as String] = service
        }
        
        if let account = configuration.account {
            query[kSecAttrAccount as String] = account
        }
        
        if let accessGroup = configuration.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        return query
    }
}

enum KeychainError: Error {
    case noPassword
    case unexpectedPasswordData
    case unexpectedItemData
    case unhandledError
}

public actor NTKeychain {
    
    private let keychainItem = KeychainItem()

    public func save(item: String, with configuration: KeychainConfiguration) throws {
        try keychainItem.saveItem(item, with: configuration)
    }
    
    public func fetchItem(configuration: KeychainConfiguration) -> String? {
        do {
            return try keychainItem.readItem(configuration: configuration)
        } catch {
            // Handle the case where no password is found
            return nil
        }
    }
    
    public func deleteItem(configuration: KeychainConfiguration) async throws {
        try keychainItem.deleteItem(configuration: configuration)
    }
}


public struct KeychainConfiguration: Sendable {
    // MARK: Properties
    /// Service, kSecAttrService, a string to identify a set of Keychain Items like “com.my-app.bundle-id”
    let service: String?
    /// Account, kSetAttrAccount, a string to identify a Keychain Item within a specific service, like “username@email.com”
    let account: String?
    /// The Access Group for the given application. This is specified under the Target's Keychain Sharing -> Keychain Group
    let accessGroup: String?
    
    public init(service: String? = nil, account: String? = nil, accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }
}
#endif
