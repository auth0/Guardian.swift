// RSAKeyPair.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
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

public class RSAKeyPair {

    public let publicKey: RSAPublicKey
    public let privateKey: RSAPrivateKey

    init(publicKey: RSAPublicKey, privateKey: RSAPrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    convenience init(publicKeyTag: String, privateKeyTag: String) {
        self.init(publicKey: RSAKeyPair.publicKey(withTag: publicKeyTag),
                  privateKey: RSAKeyPair.privateKey(withTag: privateKeyTag))
    }

    public static func new(usingPublicTag publicTag: String, privateTag: String, keySize: Int = 2048) -> RSAKeyPair? {
        var query: [String: Any] = [
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits) : keySize,
        ]
        query[String(kSecPrivateKeyAttrs)] = [
            String(kSecAttrIsPermanent)    : true,
            String(kSecAttrApplicationTag) : privateTag
        ]
        query[String(kSecPublicKeyAttrs)] = [
            String(kSecAttrIsPermanent)    : true,
            String(kSecAttrApplicationTag) : publicTag
        ]

        var privateKey: SecKey?
        var publicKey: SecKey?

        let status = SecKeyGeneratePair(query as CFDictionary, &publicKey, &privateKey)
        guard status == errSecSuccess else { return nil }
        return RSAKeyPair(publicKeyTag: publicTag, privateKeyTag: privateTag)
    }

    public static func publicKey(withTag tag: String) -> RSAPublicKey {
        return ASNPublicKey(tag: tag)
    }

    public static func privateKey(withTag tag: String) -> RSAPrivateKey {
        return SimpleRSAPrivateKey(tag: tag)
    }
}

public protocol RSAPrivateKey: KeychainRSAKey {
}

public protocol RSAPublicKey: KeychainRSAKey, JWKConvertable {
}

public protocol KeychainRSAKey {
    var tag: String { get }
}

public protocol JWKConvertable {
    var data: Data? { get }
}

extension JWKConvertable {
    private func length(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Int) {
        guard bytes.pointee > 0x7f else {
            return (bytes + 1, Int(bytes.pointee))
        }

        let count = Int(bytes.pointee & 0x7f)
        let length = (1...count).reduce(0) {
            ($0 << 8) + Int(bytes[$1])
        }
        let pointer = bytes + (1 + count)
        return (pointer, length)
    }

    private func data(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Data)? {
        guard bytes.pointee == 0x02 else { return nil }
        let (valueBytes, valueLength) = length(from: bytes + 1)
        let data = Data(bytes: valueBytes, count: valueLength)
        let pointer = valueBytes + valueLength
        return (pointer, data)
    }

    public var jwk: [String : Any]? {
        let asn = { (bytes: UnsafePointer<UInt8>) -> (Data, Data)? in
            guard bytes.pointee == 0x30 else { return nil }
            let (modulusBytes, totalLength) = self.length(from: bytes + 1)
            guard totalLength > 0, let (exponentBytes, modulus) = self.data(from: modulusBytes) else { return nil }
            guard let (end, exponent) = self.data(from: exponentBytes) else { return nil }
            guard abs(end.distance(to: modulusBytes)) == totalLength else { return nil }
            return (modulus, exponent)
        }
        guard let (modulus, exponent) = self.data?.withUnsafeBytes(asn) else { return nil }
        return [
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "e": exponent.base64URLEncodedString(),
            "n": modulus.base64URLEncodedString(),
        ]
    }
}

public extension KeychainRSAKey {
    var ref: SecKey? {
        let query: [String: Any] = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : self.tag,
            String(kSecReturnRef)          : true
        ]
        var out: AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result else {
            return nil
        }

        return (out as! SecKey)
    }
}

struct SimpleRSAPrivateKey: RSAPrivateKey {
    let tag: String
}

struct ASNPublicKey: RSAPublicKey {
    let tag: String
    var data: Data? {
        let query: [String: Any] = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : self.tag,
            String(kSecReturnData)         : true
        ]
        var out: AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &out)
        guard errSecSuccess == result else {
            return nil
        }
        return out as? Data
    }
}

