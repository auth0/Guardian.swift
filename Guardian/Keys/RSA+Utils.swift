// RSA+Utils.swift
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

func export(key: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let data: NSData = SecKeyCopyExternalRepresentation(key, &error) else {
        let cause = error!.takeRetainedValue() as Swift.Error
        throw GuardianError(code: .invalidAsymmetricKey, cause: cause)
    }
    return data as Data
}

func createKey(from data: Data) throws -> SecKey {
    let options: [String: Any] = [
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecAttrKeyClass): kSecAttrKeyClassPrivate,
        String(kSecAttrKeySizeInBits) : 2048
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(data as CFData,
                                         options as CFDictionary,
                                         &error) else {
                                            let cause = error!.takeRetainedValue() as Swift.Error
                                            throw GuardianError(code: .invalidAsymmetricKey, cause: cause)
    }
    return key
}

func publicKey(from key: SecKey) throws -> SecKey {
    guard let publicKey = SecKeyCopyPublicKey(key) else {
        throw GuardianError(code: .notFoundPublicKey)
    }
    return publicKey
}

func retrieveKey(of tag: String) throws -> SecKey {
    let query: [String: Any] = [
        String(kSecClass)              : kSecClassKey,
        String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
        String(kSecAttrApplicationTag) : tag,
        String(kSecReturnRef)          : true
    ]
    var out: CFTypeRef?
    let result = SecItemCopyMatching(query as CFDictionary, &out)
    guard errSecSuccess == result else {
        throw GuardianError(code: .notFoundPrivateKey, description: "key with tag \(tag) not found")
    }

    return (out as! SecKey)
}
