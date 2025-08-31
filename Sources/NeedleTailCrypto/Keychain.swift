//  Keychain.swift
//
//  Created by Cole M on 6/8/20.
//  Copyright © 2020 Cole M. All rights reserved.
//
//  A secure keychain implementation for iOS, macOS, tvOS, and watchOS applications.
//  Provides methods for saving, reading, and deleting keychain items with configurable
//  security options including data protection and iCloud synchronization controls.

import Foundation

/// A struct that represents a keychain item and provides methods for accessing the keychain.
private struct KeychainItem: Sendable {
    
#if !os(Android)
    /// Reads an item from the keychain.
    /// - Parameter configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if the item is not found or if there is an unexpected error.
    /// - Returns: The password as a string if found.
    fileprivate func readItem(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool = true,
        synchronizable: Bool = false
    ) throws -> String {
        var query = keychainQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        var queryResult: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &queryResult)
        
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
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Saves an item to the keychain.
    /// - Parameters:
    ///   - item: The item to save as a string.
    ///   - configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if there is an error during saving.
    fileprivate func saveItem(_ item: String,
                              with configuration: KeychainConfiguration,
                              dataProtectionEnabled: Bool = true,
                              synchronizable: Bool = false
    ) throws {
        guard let encodedItem = item.data(using: .utf8) else {
            throw KeychainError.unexpectedItemData
        }
        
        let query = keychainQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
        let status: OSStatus
        
        do {
            _ = try readItem(configuration: configuration, dataProtectionEnabled: dataProtectionEnabled, synchronizable: synchronizable)
            
            var attributesToUpdate = [String: Any]()
            attributesToUpdate[kSecValueData as String] = encodedItem
            
            status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        } catch KeychainError.noPassword {
            var newItem = query
            newItem[kSecValueData as String] = encodedItem
            
            status = SecItemAdd(newItem as CFDictionary, nil)
        }
        
        guard status == noErr else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Deletes an item from the keychain.
    /// - Parameter configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if there is an error during deletion.
    fileprivate func deleteItem(configuration: KeychainConfiguration,
                                dataProtectionEnabled: Bool = true,
                                synchronizable: Bool = false
    ) throws {
        let query = keychainQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Creates a keychain query dictionary.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: A flag indicating if the item should be stored in a data protection keychain,
    ///                            which restricts access to the item when the device is locked.
    ///                            If true, the item is accessible only when the device is unlocked.
    ///   - synchronizable: A flag indicating if the item should be synchronized across devices using iCloud Keychain.
    ///                     If true, the item will be available on all devices where the user is signed in with the same Apple ID
    ///                     and has iCloud Keychain enabled.
    /// - Returns: A dictionary representing the keychain query.
    private func keychainQuery(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecUseDataProtectionKeychain as String: dataProtectionEnabled,
            kSecAttrSynchronizable as String: synchronizable
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
#endif
    
}

/// Enum representing possible errors that can occur while accessing the keychain.
enum KeychainError: Error {
    case noPassword
    case unexpectedPasswordData
    case unexpectedItemData
#if !os(Android)
    case unhandledError(status: OSStatus)
#endif
}

/// An actor that provides a safe interface for keychain operations.
public actor NTKeychain {
    
    public init() {}
    
#if !os(Android)
    private let keychainItem = KeychainItem()
    
    // MARK: - Backward Compatible Methods (Original API)
    
    /// Saves an item to the keychain (backward compatible).
    /// - Parameters:
    ///   - item: The item to save as a string.
    ///   - configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if there is an error during saving.
    public func save(item: String, with configuration: KeychainConfiguration) throws {
        try keychainItem.saveItem(item, with: configuration)
    }
    
    /// Fetches an item from the keychain (backward compatible).
    /// - Parameter configuration: The configuration containing service, account, and access group.
    /// - Returns: The item as a string if found, or nil if not found.
    public func fetchItem(configuration: KeychainConfiguration) -> String? {
        do {
            return try keychainItem.readItem(configuration: configuration)
        } catch {
            return nil
        }
    }
    
    /// Deletes an item from the keychain (backward compatible).
    /// - Parameter configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if there is an error during deletion.
    public func deleteItem(configuration: KeychainConfiguration) async throws {
        try keychainItem.deleteItem(configuration: configuration)
    }
    
    // MARK: - Enhanced Security Methods (New API)
    
    /// Saves an item to the keychain with enhanced security options.
    /// - Parameters:
    ///   - item: The item to save as a string.
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    ///   - synchronizable: Whether to sync across devices.
    /// - Throws: `KeychainError` if there is an error during saving.
    public func save(
        item: String,
        with configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) throws {
        try keychainItem.saveItem(
            item,
            with: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable
        )
    }
    
    /// Fetches an item from the keychain with enhanced security options.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    ///   - synchronizable: Whether to sync across devices.
    /// - Returns: The item as a string if found, or nil if not found.
    /// - Throws: `KeychainError` for security-related failures.
    public func fetchItem(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) throws -> String? {
        do {
            return try keychainItem.readItem(
                configuration: configuration,
                dataProtectionEnabled: dataProtectionEnabled,
                synchronizable: synchronizable
            )
        } catch KeychainError.noPassword {
            return nil
        } catch {
            throw error
        }
    }
    
    /// Deletes an item from the keychain with enhanced security options.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    ///   - synchronizable: Whether to sync across devices.
    /// - Throws: `KeychainError` if there is an error during deletion.
    public func deleteItem(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) throws {
        try keychainItem.deleteItem(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable
        )
    }
    
    /// Checks if an item exists in the keychain without retrieving its value.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    ///   - synchronizable: Whether to sync across devices.
    /// - Returns: True if the item exists, false otherwise.
    /// - Throws: `KeychainError` for security-related failures.
    public func itemExists(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool = true,
        synchronizable: Bool = false
    ) throws -> Bool {
        do {
            _ = try keychainItem.readItem(
                configuration: configuration,
                dataProtectionEnabled: dataProtectionEnabled,
                synchronizable: synchronizable
            )
            return true
        } catch KeychainError.noPassword {
            return false
        } catch {
            throw error
        }
    }
#endif
}

/// A struct that represents the configuration for keychain access.
public struct KeychainConfiguration: Sendable {
    /// Service identifier for the keychain item (kSecAttrService).
    /// This is typically a string that identifies a set of keychain items, e.g., "com.my-app.bundle-id.some-identifier.
    public let service: String?
    
#if !os(Android)
    /// Account identifier for the keychain item (kSecAttrAccount).
    /// This is typically a string that identifies a keychain item within a specific service, e.g., "username@email.com".
    public let account: String?
    
    /// The Access Group for the given application (kSecAttrAccessGroup).
    /// This is specified under the Target's Keychain Sharing -> Keychain Group in Xcode.
    public let accessGroup: String?
    
    /// Initializes a new KeychainConfiguration.
    /// - Parameters:
    ///   - service: The service identifier for the keychain item.
    ///   - account: The account identifier for the keychain item.
    ///   - accessGroup: The access group for the keychain item.
    public init(service: String? = nil, account: String? = nil, accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }
#else
    /// Initializes a new KeychainConfiguration.
    /// - Parameters:
    ///   - service: The service identifier for the keychain item.
    public init(service: String? = nil) {
        self.service = service
    }
#endif
}


