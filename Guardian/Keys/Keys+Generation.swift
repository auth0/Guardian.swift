// Keys+Generation.swift
//
// Copyright (c) 2018 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation

private func newKey() throws -> DataRSAPrivateKey {
    let query: [String: Any] = [
        String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
        String(kSecAttrKeySizeInBits) : 2048,
        ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(query as CFDictionary, &error) else {
        let cause = error!.takeRetainedValue() as Swift.Error
        throw GuardianError(code: .failedCreationAsymmetricKey, cause: cause)
    }
    return try DataRSAPrivateKey(secKey: key)
}

private func store(key: SecKey, with tag: String, accessible: KeychainRSAPrivateKey.Accessibility = .afterFirstUnlockThisDeviceOnly) throws -> KeychainRSAPrivateKey {
    let tagData = tag.data(using: .utf8)!
    let query: [String: Any] = [
        String(kSecClass): kSecClassKey,
        String(kSecAttrApplicationTag): tagData,
        String(kSecValueRef): key,
        String(kSecAttrIsPermanent): true,
        String(kSecAttrAccessible): accessible.kSecAttr
    ]
    guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
        throw GuardianError(code: .failedStoreAsymmetricKey, description: "Cannot store key with tag \(tag) and accessible setting \(accessible)")
    }
    return KeychainRSAPrivateKey(tag: tag, secKey: key)
}

extension DataRSAPrivateKey {
    /**
     Creates a new key for signing Guardian AuthN request.
     The key will be an RSA private key w/ 2048 bits size.

     - throws: `GuardianError` if the key cannot be created
     - returns: a new RSA private key
     - important: created keys wont be stored anywhere besides memory
    */
    public static func new() throws -> DataRSAPrivateKey {
        let query: [String: Any] = [
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits) : 2048,
            ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(query as CFDictionary, &error) else {
            let cause = error!.takeRetainedValue() as Swift.Error
            throw GuardianError(code: .failedCreationAsymmetricKey, cause: cause)
        }
        return try DataRSAPrivateKey(secKey: key)
    }
}

extension KeychainRSAPrivateKey {
    /**
     Creates a new key for signing Guardian AuthN request.
     The key will be an RSA private key w/ 2048 bits size.

     - parameter tag: identifier used to store the newly created key in the iOS Keychain
     - parameter accessible: iOS Keychain item accessibility value, by defalt is after first unlock (only current device)
     - throws: `GuardianError` if the key cannot be created or stored in iOS Keychain
     - returns: a new RSA private key
     - important: Using the same tag multiple times will yield the same key found in the iOS Keychain
     */
    public static func new(with tag: String, accessible: KeychainRSAPrivateKey.Accessibility = .afterFirstUnlockThisDeviceOnly) throws -> KeychainRSAPrivateKey {
        if let existing = try? KeychainRSAPrivateKey(tag: tag) {
            return existing
        }
        let new = try newKey()
        return try store(key: new.secKey, with: tag)
    }
}

extension SigningKey {
    /**
     Stores an existing SigningKey in the iOS Keychain with a provided tag as identifier

     - parameter tag: identifier used to store the signing key
     - throws: `GuardianError` if the key cannot be stored in iOS Keychain
     - returns: an RSA private key
    */
    public func storeInKeychain(with tag: String, accessible: KeychainRSAPrivateKey.Accessibility = .afterFirstUnlockThisDeviceOnly) throws -> SigningKey {
        return try store(key: secKey, with: tag, accessible: accessible)
    }
}


