//
//  File.swift
//
//
//  Created by Cole M on 1/24/24.
//

import Crypto
import Foundation
import BSON

extension String {
    var dataRepresentation: Data {
        createData()
    }
    func createData() -> Data {
        do {
            return try BSONEncoder().encode(self).makeData()
        } catch {
            fatalError("NOT A BSON TYPE \(error)")
        }
    }
}

extension Data {
    var stringValue: String {
        deriveString()
    }
    
    func deriveString() -> String {
        do {
           return try BSONDecoder().decode(String.self, from: Document(data: self))
        } catch {
            fatalError("NOT A BSON TYPE \(error)")
        }
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
