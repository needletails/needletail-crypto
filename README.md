# NeedleTailCrypto

A comprehensive Swift cryptography library that provides a simple, secure wrapper around Swift Crypto (swift-crypto) and CryptoKit. NeedleTailCrypto simplifies encryption, decryption, key generation, and secure key storage for iOS, macOS, tvOS, and watchOS applications.

## Features

- 🔐 **Symmetric Encryption/Decryption**: AES-GCM encryption for Data and String types
- 🔑 **Key Generation**: Support for Curve25519, P256, P384, P521, and MLKEM1024 algorithms
- 🔒 **Secure Storage**: Keychain integration for secure key storage on Apple platforms
- 🛡️ **Secure Enclave**: Support for Secure Enclave on supported Apple devices
- 🔄 **Key Agreement**: ECDH key agreement for secure key exchange
- 📦 **Key Derivation**: HKDF-based key derivation from shared secrets
- ✅ **Production Ready**: Comprehensive error handling, no fatal errors, extensive test coverage

## Requirements

- Swift 6.1+
- macOS 15.0+ / iOS 18.0+
- Xcode 16.0+

## Installation

### Swift Package Manager

Add NeedleTailCrypto to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/needletail-crypto.git", from: "1.0.0")
]
```

Or add it via Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select the version you want to use

## Quick Start

### Basic Encryption/Decryption

```swift
import NeedleTailCrypto

let crypto = NeedleTailCrypto()

// Generate a symmetric key
let symmetricKey = SymmetricKey(size: .bits256)

// Encrypt data
let originalData = "Hello, World!".data(using: .utf8)!
let encrypted = try crypto.encrypt(data: originalData, symmetricKey: symmetricKey)

// Decrypt data
let decrypted = try crypto.decrypt(data: encrypted!, symmetricKey: symmetricKey)
```

### String Encryption

```swift
let crypto = NeedleTailCrypto()
let symmetricKey = SymmetricKey(size: .bits256)

// Encrypt a string
let encryptedText = try crypto.encryptText(text: "Secret message", symmetricKey: symmetricKey)

// Decrypt the string
let decryptedText = try crypto.decryptText(text: encryptedText, symmetricKey: symmetricKey)
```

### Key Generation

```swift
let crypto = NeedleTailCrypto()

// Generate Curve25519 keys
let privateKey = crypto.generateCurve25519PrivateKey()
let publicKey = privateKey.publicKey

// Generate P256 keys
let p256PrivateKey = crypto.generateP256PrivateKey()
let p256PublicKey = p256PrivateKey.publicKey

// Generate MLKEM1024 keys
let mlkemPrivateKey = try crypto.generateMLKem1024PrivateKey()
let mlkemPublicKey = mlkemPrivateKey.publicKey
```

### Key Agreement (ECDH)

```swift
let crypto = NeedleTailCrypto()

// Alice generates keys
let alicePrivateKey = crypto.generateCurve25519PrivateKey()
let alicePublicKey = alicePrivateKey.publicKey

// Bob generates keys
let bobPrivateKey = crypto.generateCurve25519PrivateKey()
let bobPublicKey = bobPrivateKey.publicKey

// Both parties derive the same shared secret
let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)

// The shared secrets are identical
assert(aliceSharedSecret.withUnsafeBytes { Data($0) } == 
       bobSharedSecret.withUnsafeBytes { Data($0) })
```

### Key Derivation

```swift
let crypto = NeedleTailCrypto()

// Derive a symmetric key from a shared secret
let salt = "unique-salt-for-this-session"
let sharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)

let symmetricKey = try crypto.derivedKeyLogic(
    salt: salt,
    cryptoAlogrythm: .curve25519(SymmetricKey(size: .bits256)),
    sharedSecret: sharedSecret
)

// Use the derived key for encryption
let encrypted = try crypto.encrypt(data: messageData, symmetricKey: symmetricKey)
```

### User Info Key (Hash-based)

```swift
let crypto = NeedleTailCrypto()

// Generate a symmetric key from a user-provided string
let userKey = "my-secret-password-12345"
let symmetricKey = try crypto.userInfoKey(userKey)

// Use for encryption
let encrypted = try crypto.encryptText(text: "Message", symmetricKey: symmetricKey)
```

### Keychain Storage (Apple Platforms)

```swift
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
let crypto = NeedleTailCrypto()

// Configure keychain
let configuration = KeychainConfiguration(
    service: "com.yourapp.keys",
    account: "user@example.com"
)

// Save a private key to keychain
try await crypto.saveKeychainPrivateKey(
    configuration: configuration,
    with: .curve25519(SymmetricKey(size: .bits256))
)

// Retrieve from keychain
if let savedKey = await crypto.fetchKeychainItem(configuration: configuration) {
    print("Retrieved key: \(savedKey)")
}

// Delete from keychain
try await crypto.deleteKeychainItem(configuration: configuration)
#endif
```

### Secure Enclave (Apple Platforms)

```swift
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
let crypto = NeedleTailCrypto()

let configuration = KeychainConfiguration(
    service: "com.yourapp.secure",
    account: "secure-key"
)

// Generate and save a Secure Enclave key
try await crypto.saveSecureEnclavePrivateKey(configuration: configuration)

// Retrieve the Secure Enclave key
let secureKey = try await crypto.getSecureEnclavePrivateKey(configuration: configuration)

// Export/Import Secure Enclave keys
let exported = try crypto.exportSecureEnclavePrivateKey(secureKey)
let imported = try crypto.importSecureEnclavePrivateKey(exported)
#endif
```

## Error Handling

NeedleTailCrypto uses Swift's error handling system. All methods that can fail are marked with `throws`:

```swift
do {
    let encrypted = try crypto.encryptText(text: "Message", symmetricKey: key)
    let decrypted = try crypto.decryptText(text: encrypted, symmetricKey: key)
} catch NeedleTailCrypto.Errors.invalidBase64Encoding {
    print("Invalid base64 data")
} catch NeedleTailCrypto.Errors.invalidUTF8Encoding {
    print("Invalid UTF-8 encoding")
} catch NeedleTailCrypto.Errors.decryptionError {
    print("Decryption failed")
} catch {
    print("Unexpected error: \(error)")
}
```

### Error Types

- `keyDataNil`: Failed to convert key string to data
- `symmetricKeyDataNil`: Failed to create symmetric key from data
- `combinedDataNil`: Encryption failed to produce combined data
- `decryptionError`: Decryption operation failed
- `secureEnclaveKeychainMismatch`: Attempted to use Secure Enclave algorithm with Keychain methods
- `invalidBase64Encoding`: Invalid base64 string provided
- `invalidUTF8Encoding`: Invalid UTF-8 encoding in string/data conversion

## API Reference

### Main Types

- `NeedleTailCrypto`: Main crypto wrapper struct
- `CryptoAlogrythm`: Enum for supported cryptographic algorithms
- `KeychainConfiguration`: Configuration for keychain operations

### Key Types

- `Curve25519PrivateKey` / `Curve25519PublicKey`
- `P256PrivateKey` / `P256PublicKey`
- `P384PrivateKey` / `P384PublicKey`
- `P521PrivateKey` / `P521PublicKey`
- `Curve25519SigningPrivateKey` / `Curve25519SigningPublicKey`
- `P256PrivateSigningKey` / `P256PublicSigningKey`
- `P384PrivateSigningKey` / `P384PublicSigningKey`
- `P521PrivateSigningKey` / `P521PublicSigningKey`

## Security Considerations

- **Key Management**: Always store private keys securely. Use Keychain on Apple platforms.
- **Nonce Reuse**: Avoid reusing nonces with the same key. The library generates random nonces by default.
- **Key Derivation**: Use unique salts for each key derivation operation.
- **Secure Enclave**: Use Secure Enclave for keys that require hardware-backed security on supported devices.

## Testing

Run the test suite:

```bash
swift test
```

Or in Xcode: Product → Test (⌘U)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For issues, questions, or contributions, please open an issue on GitHub.

