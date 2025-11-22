//
//  PrivateKey+Extension.swift
//  
//
//  Created by Cole M on 1/24/24.
//

@_exported import Crypto

extension Curve25519.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? privateKeyBase64
    }
}

extension P256.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? privateKeyBase64
    }
}

extension P384.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? privateKeyBase64
    }
}

extension P521.KeyAgreement.PrivateKey {
    var encodedKey: String {
        let rawPrivateKey = self.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        // Percent encoding with alphanumerics should never fail for base64 strings
        // If it does, return the base64 string without encoding as a safe fallback
        return privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? privateKeyBase64
    }
}
