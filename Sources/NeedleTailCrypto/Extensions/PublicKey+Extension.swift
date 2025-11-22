//
//  PublicKey+Extension.swift
//  
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto

extension Curve25519.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? base64PublicKey
    }
}

extension P521.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? base64PublicKey
    }
}

extension P384.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? base64PublicKey
    }
}

extension P256.KeyAgreement.PublicKey {
    var encodedKey: String {
        let rawPublicKey = self.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? base64PublicKey
    }
}
