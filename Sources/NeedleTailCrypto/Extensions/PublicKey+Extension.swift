//
//  PublicKey+Extension.swift
//  
//
//  Created by Cole M on 1/24/24.
//

import Crypto

extension Curve25519.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        if let key = base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return key
        }
        fatalError("PublicKey must add percent encoding")
    }
}

extension P521.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        if let key = base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return key
        }
        fatalError("PublicKey must add percent encoding")
    }
}

extension P384.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        if let key = base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return key
        }
        fatalError("PublicKey must add percent encoding")
    }
}

extension P256.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        if let key = base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) {
            return key
        }
        fatalError("PublicKey must add percent encoding")
    }
}
