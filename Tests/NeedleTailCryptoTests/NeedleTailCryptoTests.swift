//
//  NeedleTailCryptoTests.swift
//  needletail-crypto
//
//  Created by Cole M on 9/22/24.
//

import Foundation
import Testing
@testable import NeedleTailCrypto

struct NeedleTailCryptoTests {
    
    var crypto: NeedleTailCrypto {
        NeedleTailCrypto()
    }
    
    // MARK: - Encryption/Decryption Tests
    
    @Test("Encrypt and decrypt data")
    func encryptDecryptData() throws {
        let originalData = "Hello, World!".data(using: .utf8)!
        let symmetricKey = SymmetricKey(size: .bits256)
        
        let encrypted = try crypto.encrypt(data: originalData, symmetricKey: symmetricKey)
        #expect(encrypted != nil)
        
        let decrypted = try crypto.decrypt(data: encrypted!, symmetricKey: symmetricKey)
        #expect(decrypted != nil)
        #expect(decrypted == originalData)
    }
    
    @Test("Encrypt and decrypt text")
    func encryptDecryptText() throws {
        let originalText = "Hello, World! This is a test message."
        let symmetricKey = SymmetricKey(size: .bits256)
        
        let encrypted = try crypto.encryptText(text: originalText, symmetricKey: symmetricKey)
        #expect(!encrypted.isEmpty)
        
        let decrypted = try crypto.decryptText(text: encrypted, symmetricKey: symmetricKey)
        #expect(decrypted == originalText)
    }
    
    @Test("Encrypt and decrypt with custom nonce")
    func encryptDecryptWithCustomNonce() throws {
        let originalData = "Test data with custom nonce".data(using: .utf8)!
        let symmetricKey = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        
        let encrypted1 = try crypto.encrypt(data: originalData, symmetricKey: symmetricKey, nonce: nonce)
        let encrypted2 = try crypto.encrypt(data: originalData, symmetricKey: symmetricKey, nonce: nonce)
        
        // Same nonce should produce same ciphertext
        #expect(encrypted1 == encrypted2)
        
        let decrypted = try crypto.decrypt(data: encrypted1!, symmetricKey: symmetricKey)
        #expect(decrypted == originalData)
    }
    
    @Test("Decrypt text with invalid base64 throws error")
    func decryptTextWithInvalidBase64() throws {
        let symmetricKey = SymmetricKey(size: .bits256)
        
        #expect(throws: NeedleTailCrypto.Errors.invalidBase64Encoding) {
            try crypto.decryptText(text: "invalid-base64!", symmetricKey: symmetricKey)
        }
    }
    
    @Test("Decrypt text with wrong key throws error")
    func decryptTextWithWrongKey() throws {
        let originalText = "Secret message"
        let correctKey = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        
        let encrypted = try crypto.encryptText(text: originalText, symmetricKey: correctKey)
        
        // Decrypting with wrong key should fail
        #expect(throws: Error.self) {
            try crypto.decryptText(text: encrypted, symmetricKey: wrongKey)
        }
    }
    
    // MARK: - Key Generation Tests
    
    @Test("Generate Curve25519 keys")
    func generateCurve25519Keys() {
        let privateKey = crypto.generateCurve25519PrivateKey()
        let publicKey = privateKey.publicKey
        
        #expect(privateKey.rawRepresentation.count == 32)
        #expect(publicKey.rawRepresentation.count > 0)
    }
    
    @Test("Generate P256 keys")
    func generateP256Keys() {
        let privateKey = crypto.generateP256PrivateKey()
        let publicKey = privateKey.publicKey
        
        #expect(privateKey.rawRepresentation.count > 0)
        #expect(publicKey.rawRepresentation.count > 0)
    }
    
    @Test("Generate P384 keys")
    func generateP384Keys() {
        let privateKey = crypto.generateP384PrivateKey()
        let publicKey = privateKey.publicKey
        
        #expect(privateKey.rawRepresentation.count > 0)
        #expect(publicKey.rawRepresentation.count > 0)
    }
    
    @Test("Generate P521 keys")
    func generateP521Keys() {
        let privateKey = crypto.generateP521PrivateKey()
        let publicKey = privateKey.publicKey
        
        #expect(privateKey.rawRepresentation.count > 0)
        #expect(publicKey.rawRepresentation.count > 0)
    }
    
    @Test("Generate MLKEM1024 key")
    func generateMLKem1024Key() throws {
        let privateKey = try crypto.generateMLKem1024PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Verify keys are created successfully
        #expect(privateKey.publicKey.rawRepresentation.count > 0)
        #expect(publicKey.rawRepresentation.count > 0)
    }
    
    // MARK: - Key Encoding Tests
    
    @Test("Private key encoding")
    func privateKeyEncoding() {
        let privateKey = crypto.generateCurve25519PrivateKey()
        let encoded = privateKey.encodedKey
        
        #expect(!encoded.isEmpty)
        // Encoded key should be base64-like (alphanumeric with possible percent encoding)
        #expect(encoded.count > 0)
    }
    
    @Test("Public key encoding")
    func publicKeyEncoding() {
        let privateKey = crypto.generateP256PrivateKey()
        let publicKey = privateKey.publicKey
        let encoded = publicKey.encodedKey
        
        #expect(!encoded.isEmpty)
        #expect(encoded.count > 0)
    }
    
    // MARK: - Symmetric Key Derivation Tests
    
    @Test("User info key derivation")
    func userInfoKey() throws {
        let keyString = "my-secret-key-12345"
        let symmetricKey = try crypto.userInfoKey(keyString)
        
        // Same input should produce same key
        let symmetricKey2 = try crypto.userInfoKey(keyString)
        #expect(symmetricKey.withUnsafeBytes { Data($0) } == 
                symmetricKey2.withUnsafeBytes { Data($0) })
    }
    
    @Test("User info key with empty string")
    func userInfoKeyWithEmptyString() throws {
        // Empty string should still work (produces a valid symmetric key from empty data)
        _ = try crypto.userInfoKey("")
    }
    
    @Test("Symmetric key from data")
    func symmetricKeyFromData() throws {
        let data = "test data".data(using: .utf8)!
        _ = try crypto.symmetricKey(from: data)
    }
    
    // MARK: - String/Data Extension Tests
    
    @Test("String data representation")
    func stringDataRepresentation() {
        let testString = "Hello, World!"
        let data = testString.dataRepresentation
        
        #expect(!data.isEmpty)
        
        let decodedString = String(data: data, encoding: .utf8)
        #expect(decodedString == testString)
    }
    
    @Test("Data string value")
    func dataStringValue() {
        let testData = "Test data".data(using: .utf8)!
        let string = testData.stringValue
        
        #expect(!string.isEmpty)
        #expect(string == "Test data")
    }
    
    // MARK: - Key Agreement Tests
    
    @Test("Key agreement Curve25519")
    func keyAgreementCurve25519() throws {
        let alicePrivateKey = crypto.generateCurve25519PrivateKey()
        let bobPrivateKey = crypto.generateCurve25519PrivateKey()
        
        let alicePublicKey = alicePrivateKey.publicKey
        let bobPublicKey = bobPrivateKey.publicKey
        
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
        
        #expect(aliceSharedSecret.withUnsafeBytes { Data($0) } ==
                bobSharedSecret.withUnsafeBytes { Data($0) })
    }
    
    @Test("Key agreement P256")
    func keyAgreementP256() throws {
        let alicePrivateKey = crypto.generateP256PrivateKey()
        let bobPrivateKey = crypto.generateP256PrivateKey()
        
        let alicePublicKey = alicePrivateKey.publicKey
        let bobPublicKey = bobPrivateKey.publicKey
        
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
        
        #expect(aliceSharedSecret.withUnsafeBytes { Data($0) } ==
                bobSharedSecret.withUnsafeBytes { Data($0) })
    }
    
    // MARK: - Derived Key Logic Tests
    
    @Test("Derived key logic")
    func derivedKeyLogic() throws {
        let salt = "unique-salt-12345"
        let alicePrivateKey = crypto.generateCurve25519PrivateKey()
        let bobPrivateKey = crypto.generateCurve25519PrivateKey()
        
        let sharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPrivateKey.publicKey)
        _ = try crypto.derivedKeyLogic(
            salt: salt,
            cryptoAlogrythm: .curve25519(SymmetricKey(size: .bits256)),
            sharedSecret: sharedSecret
        )
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Secure Enclave keychain mismatch throws error")
    func secureEnclaveKeychainMismatch() async throws {
        #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
        let configuration = KeychainConfiguration(service: "test", account: "test")
        
        do {
            try await crypto.saveKeychainPrivateKey(
                configuration: configuration,
                with: .secureEnclave(SymmetricKey(size: .bits256))
            )
            Issue.record("Should have thrown secureEnclaveKeychainMismatch error")
        } catch let error as NeedleTailCrypto.Errors {
            #expect(error == .secureEnclaveKeychainMismatch)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
        #endif
    }
}

// MARK: - Performance Tests

@Suite("Performance Tests")
struct PerformanceTests {
    var crypto: NeedleTailCrypto {
        NeedleTailCrypto()
    }
    
    @Test("Encryption performance")
    func encryptionPerformance() throws {
        let data = Data(repeating: 0x42, count: 1024 * 1024) // 1MB
        let symmetricKey = SymmetricKey(size: .bits256)
        
        // SwiftTesting doesn't have built-in performance measurement
        // This test verifies the operation completes without errors
        let start = Date()
        _ = try crypto.encrypt(data: data, symmetricKey: symmetricKey)
        let duration = Date().timeIntervalSince(start)
        
        // Verify it completes in reasonable time (< 1 second for 1MB)
        #expect(duration < 1.0)
    }
    
    @Test("Key generation performance")
    func keyGenerationPerformance() {
        // SwiftTesting doesn't have built-in performance measurement
        // This test verifies the operations complete without errors
        let start = Date()
        _ = crypto.generateCurve25519PrivateKey()
        _ = crypto.generateP256PrivateKey()
        _ = crypto.generateP384PrivateKey()
        _ = crypto.generateP521PrivateKey()
        let duration = Date().timeIntervalSince(start)
        
        // Verify it completes in reasonable time (< 1 second)
        #expect(duration < 1.0)
    }
}
