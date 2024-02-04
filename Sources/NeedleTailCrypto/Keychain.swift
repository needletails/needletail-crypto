
//  KeychainItem.swift
//
//  Created by Cole M on 6/8/20.
//  Copyright © 2020 Cole M. All rights reserved.

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Foundation

private struct KeychainItem: Sendable {

    // MARK: Keychain access
    fileprivate func readItem(configuration: KeychainConfiguration) throws -> String {
        /*
         Build a query to find the item that matches the service, account and
         access group.
         */
        var query = keychainQuery(configuration: configuration)
        
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        // Try to fetch the existing keychain item that matches the query.
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        
        // Check the return status and throw an error if appropriate.
        guard status != errSecItemNotFound else {
            throw KeychainError.noPassword
        }
        guard status == noErr else {
            throw KeychainError.unhandledError
        }
        
        // Parse the password string from the query result.
        guard let existingItem = queryResult as? [String: AnyObject],
              let passwordData = existingItem[kSecValueData as String] as? Data,
              let password = String(data: passwordData, encoding: String.Encoding.utf8)
        else {
            throw KeychainError.unexpectedPasswordData
        }
        
        return password
    }
    
    fileprivate func saveItem(_ item: String, with configuration: KeychainConfiguration) throws {
        // Encode the password into an Data object.
        let encodedItem = item.data(using: String.Encoding.utf8)!

        do {
            // Check for an existing item in the keychain.
            try _ = readItem(configuration: configuration)
            
            // Update the existing item with the new password.
            var attributesToUpdate = [String: AnyObject]()
            attributesToUpdate[kSecValueData as String] = encodedItem as AnyObject?
            
            let query = keychainQuery(configuration: configuration)
            let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
            
            // Throw an error if an unexpected status was returned.
            guard status == noErr else {
                throw KeychainError.unhandledError
            }
        } catch KeychainError.noPassword {
            /*
             No password was found in the keychain. Create a dictionary to save
             as a new keychain item.
             */
            
            var newItem = keychainQuery(configuration: configuration)
            newItem[kSecValueData as String] = encodedItem as AnyObject?
            
            // Add a the new item to the keychain.
            let status = SecItemAdd(newItem as CFDictionary, nil)
            
            // Throw an error if an unexpected status was returned.
            guard status == noErr else {
                throw KeychainError.unhandledError
            }
        }
    }
    
    fileprivate func deleteItem(configuration: KeychainConfiguration) throws {
        // Delete the existing item from the keychain.
        let query = keychainQuery(configuration: configuration)
        let status = SecItemDelete(query as CFDictionary)
        
        // Throw an error if an unexpected status was returned.
        guard status == noErr || status == errSecItemNotFound else { throw KeychainError.unhandledError }
    }
    
    // MARK: Convenience
//    private func keychainQuery(withService
//                                      service: String? = nil,
//                                      account: String? = nil,
//                                      accessGroup: String? = nil
//    ) -> [String: AnyObject] {
//        
//        var query = [String: AnyObject]()
//        query[kSecClass as String] = kSecClassGenericPassword
//        query[kSecAttrService as String] = service as AnyObject?
//        query[kSecAttrSynchronizable as String] = kCFBooleanTrue
//        
//        if let account = account {
//            query[kSecAttrAccount as String] = account as AnyObject?
//        }
//        
//        if let accessGroup = accessGroup {
//            query[kSecAttrAccessGroup as String] = accessGroup as AnyObject?
//        }
//        return query
//    }
    
    private func keychainQuery(configuration: KeychainConfiguration) -> [String: Any] {
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
    
    fileprivate let keychainItem = KeychainItem()

    public func save(item: String, with configuration: KeychainConfiguration) throws {
        try keychainItem.saveItem(item, with: configuration)
    }
    
    
    public func fetchItem(configuration: KeychainConfiguration) throws -> String? {
        try keychainItem.readItem(configuration: configuration)
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
