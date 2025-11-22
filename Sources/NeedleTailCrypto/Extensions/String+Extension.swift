//
//  String+Extension.swift
//
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto
import Foundation

extension String {
    var dataRepresentation: Data {
        createData()
    }
    func createData() -> Data {
        // UTF-8 encoding should never fail for valid Swift strings
        // If it does, return empty data as a safe fallback
        self.data(using: .utf8) ?? Data()
    }
}

extension Data {
    var stringValue: String {
        deriveString()
    }
    
    func deriveString() -> String {
        // UTF-8 decoding should succeed for valid UTF-8 data
        // If it fails, return empty string as a safe fallback
        String(data: self, encoding: .utf8) ?? ""
    }
}

extension NeedleTailCrypto {
    
    func derivedSymmetricKey(
        sharedSecret: SharedSecret,
        salt: Data
    ) throws -> SymmetricKey {
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(),
            outputByteCount: 32
        )
    }
    
    public func deriveStrictSymmetricKey(data: Data, salt: Data) async -> SymmetricKey {
        let symmetricKey = SymmetricKey(data: SHA512.hash(data: data))
        return HKDF<SHA512>.deriveKey(inputKeyMaterial: symmetricKey, salt: data, outputByteCount: 256 / 8)
    }
}
