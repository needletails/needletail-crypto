//  Keychain.swift
//
//  Created by Cole M on 6/8/20.
//  Copyright © 2020 Cole M. All rights reserved.
//
//  A secure keychain implementation for iOS, macOS, tvOS, and watchOS applications.
//  Provides methods for saving, reading, and deleting keychain items with configurable
//  security options including data protection, accessibility class and iCloud synchronization controls.

import Foundation

/// A struct that represents a keychain item and provides methods for accessing the keychain.
private struct KeychainItem: Sendable {
    
#if !os(Android) && !os(Linux)
    /// Reads an item from the keychain.
    /// - Parameter configuration: The configuration containing service, account, and access group.
    /// - Throws: `KeychainError` if the item is not found or if there is an unexpected error.
    /// - Returns: The password as a string if found.
    fileprivate func readItem(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool = true,
        synchronizable: Bool = false
    ) throws -> String {
        let query = KeychainQueryBuilder.readQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
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
    ///   - accessibility: The accessibility class for the item. Saving over an existing item also moves it to this class.
    /// - Throws: `KeychainError` if there is an error during saving.
    fileprivate func saveItem(_ item: String,
                              with configuration: KeychainConfiguration,
                              dataProtectionEnabled: Bool = true,
                              synchronizable: Bool = false,
                              accessibility: KeychainAccessibility = .whenUnlocked
    ) throws {
        guard let encodedItem = item.data(using: .utf8) else {
            throw KeychainError.unexpectedItemData
        }
        
        let query = KeychainQueryBuilder.matchQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
        let status: OSStatus
        
        do {
            _ = try readItem(configuration: configuration, dataProtectionEnabled: dataProtectionEnabled, synchronizable: synchronizable)
            
            let attributesToUpdate = KeychainQueryBuilder.updateAttributes(
                encodedItem,
                accessibility: accessibility)
            
            status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        } catch KeychainError.noPassword {
            let newItem = KeychainQueryBuilder.addQuery(
                encodedItem,
                configuration: configuration,
                dataProtectionEnabled: dataProtectionEnabled,
                synchronizable: synchronizable,
                accessibility: accessibility)
            
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
        let query = KeychainQueryBuilder.matchQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Moves every non-synchronizable generic password item for an account to an accessibility class.
    /// - Parameters:
    ///   - accessibility: The accessibility class to move the items to.
    ///   - account: The account identifier (kSecAttrAccount) whose items to update.
    /// - Throws: `KeychainError` if there is an error during the update. Finding no items isn't an error.
    fileprivate func updateAccessibility(
        to accessibility: KeychainAccessibility,
        account: String,
        dataProtectionEnabled: Bool = true
    ) throws {
        let query = KeychainQueryBuilder.accountQuery(
            account: account,
            dataProtectionEnabled: dataProtectionEnabled)
        let attributesToUpdate = KeychainQueryBuilder.accessibilityAttributes(accessibility)
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
#endif
    
}

#if !os(Android) && !os(Linux)
/// Builds the dictionaries passed to the keychain's `SecItem` functions.
///
/// Queries that match items (read, update and delete) never include `kSecAttrAccessible`. The accessibility class
/// isn't part of a generic password's uniqueness, so at most one item matches a service and account, and an item
/// is found whatever class it was stored with. Only the dictionaries that add or update an item set the class.
enum KeychainQueryBuilder {
    
    /// Creates a query that matches the item for a configuration.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: A flag indicating if the item should be stored in a data protection keychain
    ///                            (kSecUseDataProtectionKeychain), where the item's accessibility class controls
    ///                            whether it can be read while the device is locked.
    ///   - synchronizable: A flag indicating if the item should be synchronized across devices using iCloud Keychain.
    ///                     If true, the item will be available on all devices where the user is signed in with the same Apple ID
    ///                     and has iCloud Keychain enabled.
    /// - Returns: A dictionary representing the keychain query.
    static func matchQuery(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
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
    
    /// Creates a query that returns the attributes and data of the item for a configuration.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: A flag indicating if the item is stored in a data protection keychain.
    ///   - synchronizable: A flag indicating if the item is synchronized across devices using iCloud Keychain.
    /// - Returns: A dictionary representing the keychain query.
    static func readQuery(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool
    ) -> [String: Any] {
        var query = matchQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        return query
    }
    
    /// Creates the dictionary that adds a new item for a configuration.
    /// - Parameters:
    ///   - data: The item's data.
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: A flag indicating if the item should be stored in a data protection keychain.
    ///   - synchronizable: A flag indicating if the item should be synchronized across devices using iCloud Keychain.
    ///   - accessibility: The accessibility class for the new item.
    /// - Returns: A dictionary representing the item to add.
    static func addQuery(
        _ data: Data,
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool,
        accessibility: KeychainAccessibility
    ) -> [String: Any] {
        var item = matchQuery(
            configuration: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable)
        
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = accessibility.secAttrAccessible
        
        return item
    }
    
    /// Creates the attributes that replace an existing item's data and move it to an accessibility class.
    /// - Parameters:
    ///   - data: The item's new data.
    ///   - accessibility: The accessibility class for the item.
    /// - Returns: A dictionary of the attributes to update.
    static func updateAttributes(_ data: Data, accessibility: KeychainAccessibility) -> [String: Any] {
        [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility.secAttrAccessible
        ]
    }
    
    /// Creates a query that matches every non-synchronizable generic password item for an account, across all services.
    /// - Parameters:
    ///   - account: The account identifier (kSecAttrAccount) to match.
    ///   - dataProtectionEnabled: A flag indicating if the items are stored in a data protection keychain.
    /// - Returns: A dictionary representing the keychain query.
    static func accountQuery(account: String, dataProtectionEnabled: Bool) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: dataProtectionEnabled,
            kSecAttrSynchronizable as String: false
        ]
    }
    
    /// Creates the attributes that move matched items to an accessibility class.
    /// - Parameter accessibility: The accessibility class for the items.
    /// - Returns: A dictionary of the attributes to update.
    static func accessibilityAttributes(_ accessibility: KeychainAccessibility) -> [String: Any] {
        [kSecAttrAccessible as String: accessibility.secAttrAccessible]
    }
}
#endif

/// Enum representing possible errors that can occur while accessing the keychain.
enum KeychainError: Error {
    case noPassword
    case unexpectedPasswordData
    case unexpectedItemData
#if !os(Android) && !os(Linux)
    case unhandledError(status: OSStatus)
#endif
}

/// An actor that provides a safe interface for keychain operations.
public actor NTKeychain {
    
    public init() {}
    
#if !os(Android) && !os(Linux)
    private let keychainItem = KeychainItem()
    
    // MARK: - Backward Compatible Methods (Original API)
    
    /// Saves an item to the keychain (backward compatible).
    /// - Parameters:
    ///   - item: The item to save as a string.
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - accessibility: The accessibility class for the item. Defaults to `.whenUnlocked`.
    ///                    Saving over an existing item also moves it to this class.
    /// - Throws: `KeychainError` if there is an error during saving.
    public func save(
        item: String,
        with configuration: KeychainConfiguration,
        accessibility: KeychainAccessibility = .whenUnlocked
    ) throws {
        try keychainItem.saveItem(item, with: configuration, accessibility: accessibility)
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
    ///   - accessibility: The accessibility class for the item. Defaults to `.whenUnlocked`.
    ///                    Saving over an existing item also moves it to this class.
    /// - Throws: `KeychainError` if there is an error during saving.
    public func save(
        item: String,
        with configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool,
        synchronizable: Bool,
        accessibility: KeychainAccessibility = .whenUnlocked
    ) throws {
        try keychainItem.saveItem(
            item,
            with: configuration,
            dataProtectionEnabled: dataProtectionEnabled,
            synchronizable: synchronizable,
            accessibility: accessibility
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
    
    // MARK: - Accessibility Methods
    
    /// Fetches an item from the keychain, telling a missing item apart from one that can't be read
    /// because the device is locked.
    ///
    /// Use this where a locked device must not be mistaken for a missing item, for example in work
    /// started by a silent push while the device is locked.
    /// - Parameters:
    ///   - configuration: The configuration containing service, account, and access group.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    ///   - synchronizable: Whether to sync across devices.
    /// - Returns: `.found` with the item, `.absent` if no item matches, or `.locked` if the keychain refused
    ///            the read because the device is locked (`errSecInteractionNotAllowed`).
    /// - Throws: `KeychainError` for any other failure, such as item data that isn't UTF-8 or an unexpected status.
    ///           These are thrown rather than reported as `.absent`, so an unreadable item is never mistaken for a missing one.
    public func fetchItemResult(
        configuration: KeychainConfiguration,
        dataProtectionEnabled: Bool = true,
        synchronizable: Bool = false
    ) throws -> KeychainFetchResult {
        do {
            return .found(try keychainItem.readItem(
                configuration: configuration,
                dataProtectionEnabled: dataProtectionEnabled,
                synchronizable: synchronizable
            ))
        } catch {
            guard let result = KeychainFetchResult(readError: error) else {
                throw error
            }
            return result
        }
    }
    
    /// Moves every generic password item for an account to an accessibility class in one update.
    ///
    /// The update matches items by account across all services and every access group the app can use,
    /// and skips synchronizable items. Run it while the device is unlocked: an item stored as `.whenUnlocked`
    /// can't be changed while the device is locked. Running it again is harmless.
    /// - Parameters:
    ///   - accessibility: The accessibility class to move the items to.
    ///   - account: The account identifier (kSecAttrAccount) whose items to update.
    ///   - dataProtectionEnabled: Whether to use data protection keychain.
    /// - Throws: `KeychainError` if there is an error during the update. Finding no items isn't an error.
    public func migrateAccessibility(
        to accessibility: KeychainAccessibility,
        account: String,
        dataProtectionEnabled: Bool = true
    ) throws {
        try keychainItem.updateAccessibility(
            to: accessibility,
            account: account,
            dataProtectionEnabled: dataProtectionEnabled
        )
    }
#endif
}

/// A struct that represents the configuration for keychain access.
public struct KeychainConfiguration: Sendable {
    /// Service identifier for the keychain item (kSecAttrService).
    /// This is typically a string that identifies a set of keychain items, e.g., "com.my-app.bundle-id.some-identifier.
    public let service: String?
    
#if !os(Android) && !os(Linux)
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

/// An enum representing when a keychain item's data can be read (kSecAttrAccessible).
/// The class also controls whether the item moves to a new device through an encrypted backup.
public enum KeychainAccessibility: Sendable, CaseIterable {
    /// The item can be read only while the device is unlocked (kSecAttrAccessibleWhenUnlocked).
    /// The item moves to a new device through an encrypted backup. This is the default class.
    case whenUnlocked
    
    /// The item can be read only while the device is unlocked (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
    /// The item never leaves this device and can't be synchronizable.
    case whenUnlockedThisDeviceOnly
    
    /// The item can be read once the device has been unlocked after a restart, including while it's locked again
    /// (kSecAttrAccessibleAfterFirstUnlock). The item moves to a new device through an encrypted backup.
    case afterFirstUnlock
    
    /// The item can be read once the device has been unlocked after a restart, including while it's locked again
    /// (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly). The item never leaves this device and can't be synchronizable.
    /// Use this for items that background work, such as handling a silent push, reads while the device is locked.
    case afterFirstUnlockThisDeviceOnly
}

#if !os(Android) && !os(Linux)
extension KeychainAccessibility {
    /// The keychain constant for this class, used as the value of `kSecAttrAccessible`.
    var secAttrAccessible: CFString {
        switch self {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
}
#endif

/// An enum representing the outcome of fetching a keychain item.
/// It tells a missing item apart from one that can't be read yet because the device is locked.
public enum KeychainFetchResult: Sendable, Equatable {
    /// The item was found.
    case found(String)
    
    /// No item matches the configuration.
    case absent
    
    /// The keychain refused the read because the device is locked (errSecInteractionNotAllowed).
    /// The item may exist; try again once the device has been unlocked.
    case locked
}

#if !os(Android) && !os(Linux)
extension KeychainFetchResult {
    /// Maps an error thrown while reading an item to a result.
    /// - Parameter error: The error thrown by the read.
    /// - Returns: `.absent` for a missing item, `.locked` for a read refused because the device is locked,
    ///            or nil for any other error, which the caller should throw.
    init?(readError error: Error) {
        guard let error = error as? KeychainError else {
            return nil
        }
        
        switch error {
        case .noPassword, .unhandledError(status: errSecItemNotFound):
            self = .absent
        case .unhandledError(status: errSecInteractionNotAllowed):
            self = .locked
        default:
            return nil
        }
    }
}
#endif


