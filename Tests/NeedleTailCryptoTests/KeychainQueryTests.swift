//
//  KeychainQueryTests.swift
//  needletail-crypto
//

#if !os(Android) && !os(Linux)
import Foundation
import Testing
@testable import NeedleTailCrypto

@Suite("Keychain Query Tests")
struct KeychainQueryTests {
    
    let configuration = KeychainConfiguration(service: "service", account: "account", accessGroup: "group")
    let data = Data("secret".utf8)
    
    // MARK: - Match Queries
    
    @Test("Match query identifies the item without an accessibility class")
    func matchQueryExcludesAccessibility() {
        let query = KeychainQueryBuilder.matchQuery(
            configuration: configuration,
            dataProtectionEnabled: true,
            synchronizable: false)
        
        #expect(query[kSecAttrAccessible as String] == nil)
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrService as String] as? String == "service")
        #expect(query[kSecAttrAccount as String] as? String == "account")
        #expect(query[kSecAttrAccessGroup as String] as? String == "group")
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
    }
    
    @Test("Match query omits configuration fields that aren't set")
    func matchQueryOmitsUnsetFields() {
        let query = KeychainQueryBuilder.matchQuery(
            configuration: KeychainConfiguration(service: "service"),
            dataProtectionEnabled: false,
            synchronizable: true)
        
        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == false)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
    }
    
    @Test("Read query returns one item's data without an accessibility class")
    func readQueryExcludesAccessibility() {
        let query = KeychainQueryBuilder.readQuery(
            configuration: configuration,
            dataProtectionEnabled: true,
            synchronizable: false)
        
        #expect(query[kSecAttrAccessible as String] == nil)
        #expect(query[kSecAttrService as String] as? String == "service")
        #expect(query[kSecAttrAccount as String] as? String == "account")
        #expect(query[kSecMatchLimit as String] as? String == kSecMatchLimitOne as String)
        #expect(query[kSecReturnAttributes as String] as? Bool == true)
        #expect(query[kSecReturnData as String] as? Bool == true)
    }
    
    // MARK: - Writes
    
    @Test("Add query sets the requested accessibility class", arguments: KeychainAccessibility.allCases)
    func addQueryIncludesAccessibility(accessibility: KeychainAccessibility) {
        let query = KeychainQueryBuilder.addQuery(
            data,
            configuration: configuration,
            dataProtectionEnabled: true,
            synchronizable: false,
            accessibility: accessibility)
        
        #expect(query[kSecAttrAccessible as String] as? String == accessibility.secAttrAccessible as String)
        #expect(query[kSecValueData as String] as? Data == data)
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrService as String] as? String == "service")
        #expect(query[kSecAttrAccount as String] as? String == "account")
        #expect(query[kSecAttrAccessGroup as String] as? String == "group")
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
    }
    
    @Test("Update attributes set the data and the requested accessibility class", arguments: KeychainAccessibility.allCases)
    func updateAttributesIncludeAccessibility(accessibility: KeychainAccessibility) {
        let attributes = KeychainQueryBuilder.updateAttributes(data, accessibility: accessibility)
        
        #expect(attributes.count == 2)
        #expect(attributes[kSecValueData as String] as? Data == data)
        #expect(attributes[kSecAttrAccessible as String] as? String == accessibility.secAttrAccessible as String)
    }
    
    // MARK: - Migration
    
    @Test("Account query matches every non-synchronizable item for the account")
    func accountQueryMatchesAccount() {
        let query = KeychainQueryBuilder.accountQuery(account: "Nudge", dataProtectionEnabled: true)
        
        #expect(query.count == 4)
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrAccount as String] as? String == "Nudge")
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
    }
    
    @Test("Migration attributes set only the requested accessibility class", arguments: KeychainAccessibility.allCases)
    func accessibilityAttributesIncludeAccessibility(accessibility: KeychainAccessibility) {
        let attributes = KeychainQueryBuilder.accessibilityAttributes(accessibility)
        
        #expect(attributes.count == 1)
        #expect(attributes[kSecAttrAccessible as String] as? String == accessibility.secAttrAccessible as String)
    }
    
    // MARK: - Accessibility
    
    @Test("Accessibility maps to the keychain constants")
    func accessibilityConstants() {
        #expect(KeychainAccessibility.whenUnlocked.secAttrAccessible as String
                == kSecAttrAccessibleWhenUnlocked as String)
        #expect(KeychainAccessibility.whenUnlockedThisDeviceOnly.secAttrAccessible as String
                == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(KeychainAccessibility.afterFirstUnlock.secAttrAccessible as String
                == kSecAttrAccessibleAfterFirstUnlock as String)
        #expect(KeychainAccessibility.afterFirstUnlockThisDeviceOnly.secAttrAccessible as String
                == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }
    
    // MARK: - Fetch Results
    
    @Test("Missing item reads as absent")
    func missingItemIsAbsent() {
        #expect(KeychainFetchResult(readError: KeychainError.noPassword) == .absent)
        #expect(KeychainFetchResult(readError: KeychainError.unhandledError(status: errSecItemNotFound)) == .absent)
    }
    
    @Test("Read refused while locked reads as locked")
    func interactionNotAllowedIsLocked() {
        #expect(KeychainFetchResult(readError: KeychainError.unhandledError(status: errSecInteractionNotAllowed)) == .locked)
    }
    
    @Test("Other read errors aren't mapped")
    func otherErrorsAreNotMapped() {
        #expect(KeychainFetchResult(readError: KeychainError.unexpectedPasswordData) == nil)
        #expect(KeychainFetchResult(readError: KeychainError.unhandledError(status: errSecAuthFailed)) == nil)
        #expect(KeychainFetchResult(readError: CocoaError(.fileNoSuchFile)) == nil)
    }
}
#endif
