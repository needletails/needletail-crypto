//
//  PrivateKey+Extension.swift
//  
//
//  Created by Cole M on 1/24/24.
//

import Crypto


extension Curve25519.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        if let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return percentEncodedPrivateKey
        }
        fatalError("Could not add percent encoding to private key")
    }
}

extension P256.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        if let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return percentEncodedPrivateKey
        }
        fatalError("Could not add percent encoding to private key")
    }
}

extension P384.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        if let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return percentEncodedPrivateKey
        }
        fatalError("Could not add percent encoding to private key")
    }
}

extension P521.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        if let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return percentEncodedPrivateKey
        }
        fatalError("Could not add percent encoding to private key")
    }
}

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
extension SecureEnclave.P256.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.dataRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        if let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return percentEncodedPrivateKey
        }
        fatalError("Could not add percent encoding to private key")
    }
}
#endif
